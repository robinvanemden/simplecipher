/*
 * nb_io.h — Non-blocking frame I/O for chat loops
 *
 * State machine for incremental TCP frame read/write using poll().
 * Used by all POSIX chat loops; Windows has its own event-driven model.
 *
 * Inbound: two-phase accumulation [pad_len(1)][frame(512)][random_pad].
 * Outbound: frame_build → frame_wire_build → incremental drain via POLLOUT.
 *
 * All helpers are pure logic — UI feedback (error messages, display)
 * stays in the calling loop.
 *
 * Read next: cli_posix.c, tui_posix.c (consumers), network.h (wire format)
 */

#ifndef SIMPLECIPHER_NB_IO_H
#define SIMPLECIPHER_NB_IO_H

#include "protocol.h" /* FRAME_SZ, WIRE_MAX, WIRE_HDR, KEY, MAX_MSG, session_t */

/* ---- Non-blocking I/O state -------------------------------------------- */

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

/* ---- Lifecycle --------------------------------------------------------- */

void nb_io_init(nb_io_t *io);
void nb_io_wipe(nb_io_t *io);

/* ---- Low-level non-blocking socket I/O --------------------------------- */

/* Returns bytes read (>0), 0 if EAGAIN (no data), -1 on error/disconnect.
 * Handles EINTR internally (retries if g_running is true). */
int nb_try_recv(socket_t fd, void *buf, size_t n);

/* Returns bytes sent (>0), 0 if EAGAIN (buffer full), -1 on error.
 * Uses MSG_NOSIGNAL on POSIX to suppress SIGPIPE. */
int nb_try_send(socket_t fd, const void *buf, size_t n);

/* ---- Inbound frame accumulation ---------------------------------------- */

/* Result codes for nb_io_accumulate. */
enum {
    NB_RECV_INCOMPLETE =  0, /* need more bytes — poll again        */
    NB_RECV_FRAME      =  1, /* complete frame in io->in_wire       */
    NB_RECV_DISCONNECT = -1, /* peer closed or I/O error            */
};

/* Read available bytes from fd, advance the two-phase state machine.
 * On NB_RECV_FRAME: the frame is at io->in_wire + WIRE_HDR.
 * Caller must frame_open() and then call nb_io_reset_recv(io). */
int nb_io_accumulate(nb_io_t *io, socket_t fd);

/* Reset inbound state after processing a complete frame. */
void nb_io_reset_recv(nb_io_t *io);

/* ---- Outbound frame drain ---------------------------------------------- */

/* Result codes for nb_io_drain. */
enum {
    NB_SEND_INCOMPLETE =  0, /* partial send — poll POLLOUT again   */
    NB_SEND_COMPLETE   =  1, /* all bytes sent                      */
    NB_SEND_ERROR      = -1, /* I/O error                           */
};

/* Write available bytes from io->out_wire to fd. */
int nb_io_drain(nb_io_t *io, socket_t fd);

/* ---- Send lifecycle ---------------------------------------------------- */

/* Build a frame from payload, wire-encode it, and begin async send.
 * Sets io->out_active, tries an immediate nb_try_send.
 * msg_text is copied into io->out_text for display on completion
 * (pass NULL or "" for cover frames with no display).
 * Returns 0 on success (send started or completed), -1 on frame_build error. */
[[nodiscard]] int nb_io_start_send(nb_io_t *io, session_t *sess, socket_t fd,
                                   const uint8_t *payload, uint16_t len,
                                   const char *msg_text);

/* Commit tx chain state after a completed send.
 * IMPORTANT: read io->out_text BEFORE calling this — it wipes out_text.
 * Copies out_next_tx → sess->tx, increments tx_seq, wipes send buffers,
 * clears out_active. */
void nb_io_complete_send(nb_io_t *io, session_t *sess);

/* ---- Deadline checks --------------------------------------------------- */

/* Returns 1 if a partial inbound frame has exceeded FRAME_TIMEOUT_S. */
int nb_io_recv_deadline_expired(const nb_io_t *io);

/* Returns 1 if an outbound send has exceeded FRAME_TIMEOUT_S. */
int nb_io_send_deadline_expired(const nb_io_t *io);

#endif /* SIMPLECIPHER_NB_IO_H */
