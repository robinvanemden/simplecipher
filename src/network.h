/*
 * network.h — TCP networking for SimpleCipher
 *
 * This module handles all TCP socket I/O: setting timeouts and options,
 * reading/writing exact byte counts, the simultaneous exchange helper
 * used during the handshake, and the connect/listen socket setup.
 *
 * The protocol layer (protocol.h) builds encrypted frames; this module
 * moves those frames over the wire without knowing or caring about their
 * contents.
 *
 * Read next: tui.h or cli.h (user interface event loops)
 */

#ifndef SIMPLECIPHER_NETWORK_H
#define SIMPLECIPHER_NETWORK_H

#include "platform.h"
#include "protocol.h"

/* Set a receive/send timeout of 'secs' seconds on the socket.
 * Used during the handshake to disconnect a stalled peer automatically.
 * Pass secs=0 to remove the timeout after the handshake completes. */
void set_sock_timeout(socket_t fd, int secs);

/* Enable TCP keepalives and disable Nagle's algorithm on the socket.
 * See network.c for the rationale behind each option. */
void set_sock_opts(socket_t fd);

/* Read exactly n bytes from fd into buf, looping on partial reads.
 * TCP is a stream: a single recv() may return fewer bytes than asked for.
 * Returns 0 when all n bytes are in buf, -1 on error or peer close. */
[[nodiscard]] int read_exact(socket_t fd, void *buf, size_t n);

/* Write exactly n bytes from buf to fd, looping on partial writes.
 * MSG_NOSIGNAL suppresses SIGPIPE on Linux when the peer closes. */
[[nodiscard]] int write_exact(socket_t fd, const void *buf, size_t n);

/* Deadline-aware variants: return -1 if monotonic_ms() exceeds
 * deadline_ms between partial reads/writes.  Defeats byte-dribble
 * attacks where an adversary sends one byte just under SO_RCVTIMEO
 * to keep the connection alive indefinitely.  Pass 0 for no deadline. */
[[nodiscard]] int read_exact_dl(socket_t fd, void *buf, size_t n, uint64_t deadline_ms);
[[nodiscard]] int write_exact_dl(socket_t fd, const void *buf, size_t n, uint64_t deadline_ms);

/* Exchange one value simultaneously with the peer.
 * The initiator sends first to avoid both sides waiting for each other.
 * Each message is padded with 0-127 random bytes (DPI resistance). */
[[nodiscard]] int exchange(socket_t fd, int we_init, const uint8_t *out, size_t out_n, uint8_t *in, size_t in_n);

/* Build a padded wire message: [pad_len(1)][frame][random_pad].
 * pad_len is a raw CSPRNG byte — uniform random, no detectable pattern.
 * Returns the total wire length (513-768 bytes).
 * wire must be at least WIRE_MAX bytes. */
size_t frame_wire_build(uint8_t *wire, const uint8_t *frame);

/* Send one frame with random padding over TCP (blocking).
 * Wire format: [pad_len(1)][frame(512)][random_pad(0-255)].
 * Pass deadline_ms=0 for no deadline. */
[[nodiscard]] int frame_send(socket_t fd, const uint8_t *frame, uint64_t deadline_ms);

/* Receive one padded frame from TCP (blocking).
 * Reads 1-byte pad_len, then the frame, then drains padding.
 * Pass deadline_ms=0 for no deadline. */
[[nodiscard]] int frame_recv(socket_t fd, uint8_t *frame, uint64_t deadline_ms);

/* Connect to host:port, trying all addresses getaddrinfo returns.
 * Returns the connected socket, or INVALID_SOCK on failure. */
[[nodiscard]] socket_t connect_socket(const char *host, const char *port);

/* Connect to a numeric IP:port only (AI_NUMERICHOST) — no DNS.
 * Use for direct connect on Android and desktop to prevent
 * metadata leakage to the local resolver. */
[[nodiscard]] socket_t connect_socket_numeric(const char *host, const char *port);

/* Bind to port, accept exactly one connection, close the listener.
 * One peer only -- this is not a server. */
[[nodiscard]] socket_t listen_socket(const char *port);

/* Like listen_socket, but calls on_idle() periodically (every ~250ms)
 * while waiting for a connection.  Allows TUI redraws on resize.
 * on_idle receives its opaque context pointer.  */
[[nodiscard]] socket_t listen_socket_cb(const char *port, void (*on_idle)(void *ctx), void *ctx);

/* Connect through a SOCKS5 proxy (RFC 1928).
 * Opens TCP to the proxy, negotiates SOCKS5 no-auth, sends a CONNECT
 * request for target_host:target_port, then returns the connected socket.
 * The caller uses this socket exactly like one from connect_socket(). */
[[nodiscard]] socket_t connect_socket_socks5(const char *proxy_host, const char *proxy_port, const char *target_host,
                                             const char *target_port);

/* Print non-loopback IP addresses so the user can tell their peer where
 * to connect.  Skips link-local (169.254.x.x, fe80::) and loopback. */
void print_local_ips(const char *port);

/* Collect non-loopback IPv4 addresses into buf as newline-separated strings.
 * Returns the number of addresses found.  Each line is "ip_address".
 * buf_sz is the total buffer size; output is null-terminated. */
int get_local_ips(char *buf, size_t buf_sz);

/* ---- Non-blocking frame I/O (POSIX chat loops) ------------------------- */

/* State for incremental, non-blocking frame read/write.
 * Used by the POSIX chat loops after the socket is set non-blocking.
 * Windows uses its own event-driven state machine. */
typedef struct {
    /* Inbound: accumulate [pad_len(1)][frame(512)][random_pad(0-255)] */
    uint8_t  in_wire[WIRE_MAX];
    size_t   in_have;             /* bytes accumulated so far           */
    size_t   in_need;             /* bytes needed for current phase     */
    uint64_t in_start_ms;         /* monotonic timestamp of first byte  */

    /* Outbound: drain a pre-built wire message */
    uint8_t  out_wire[WIRE_MAX];
    size_t   out_len;             /* total wire message length           */
    size_t   out_off;             /* bytes sent so far                   */
    int      out_active;          /* 1 if a send is in flight            */
    uint64_t out_start_ms;        /* monotonic timestamp of send start   */
    uint8_t  out_next_tx[KEY];    /* next tx chain key (committed on completion) */
    char     out_text[MAX_MSG+1]; /* message text for display on completion */
} nb_io_t;

/* Initialize / wipe non-blocking I/O state. */
void nb_io_init(nb_io_t *io);
void nb_io_wipe(nb_io_t *io);

/* Non-blocking recv: read available bytes from fd into buf.
 * Returns bytes read (>0), 0 if EAGAIN (no data), -1 on error/disconnect. */
int nb_try_recv(socket_t fd, void *buf, size_t n);

/* Non-blocking send: write available bytes from buf to fd.
 * Returns bytes sent (>0), 0 if EAGAIN (buffer full), -1 on error. */
int nb_try_send(socket_t fd, const void *buf, size_t n);

/* ---- SOCKS5 helpers (pure, testable) ------------------------------------ */

/* Maximum SOCKS5 CONNECT request size: 4 header + 1 len + 255 host + 2 port */
enum { SOCKS5_REQ_MAX = 262 };

/* Build a SOCKS5 CONNECT request.  Returns request length, or 0 on invalid
 * input (null pointers, empty host, host > 255 bytes, port out of range).
 * buf must be at least SOCKS5_REQ_MAX bytes. */
int socks5_build_request(uint8_t *buf, size_t buf_sz, const char *host, const char *port_str);

/* Compute bytes to skip after SOCKS5 reply header, based on address type.
 * For atyp 0x03, caller must read the 1-byte domain length first.
 * Returns -1 for unknown atyp. */
int socks5_reply_skip(uint8_t atyp, uint8_t domain_len);

#endif /* SIMPLECIPHER_NETWORK_H */
