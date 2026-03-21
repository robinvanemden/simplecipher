/*
 * protocol.h — Chat protocol for SimpleCipher
 *
 * This module defines the wire protocol: frame layout, session key
 * derivation, and message encryption/decryption.
 *
 * Frame layout (always exactly 512 bytes -- hides message length):
 *   [ seq : 8 ][ ciphertext : 488 ][ mac : 16 ]
 *   seq is authenticated additional data (not encrypted, but tamper-proof).
 *
 * Plaintext slot: [ len(2) | message(<=486) | zero padding ]
 *
 * Session key derivation (see session_init in protocol.c):
 *   ikm      = dh_shared_secret || initiator_pub || responder_pub
 *   prk      = domain_hash("cipher x25519 sas root v1", ikm)
 *   sas_key  = expand(prk, "sas")
 *   tx_chain = expand(prk, direction)
 *   rx_chain = expand(prk, direction)
 *
 * The commit-after-send pattern ensures both sides stay in sync:
 * the chain is advanced only after a successful network write.
 *
 * Read next: network.h (TCP I/O) or crypto.h (cryptographic primitives)
 */

#ifndef SIMPLECIPHER_PROTOCOL_H
#define SIMPLECIPHER_PROTOCOL_H

#include "crypto.h"

/* ---- frame constants ---------------------------------------------------- */

static constexpr int FRAME_SZ             = 512;   /* every frame is exactly this  */
static constexpr int AD_SZ                = 8;     /* additional data = seq number */
static constexpr int CT_SZ                = FRAME_SZ - AD_SZ - MAC_SZ; /* ciphertext slot = 488 bytes */
static constexpr int MAX_MSG              = CT_SZ - 2;    /* 2 bytes reserved for length */
static constexpr int PROTOCOL_VERSION     = 1;     /* increment if frame layout or KDF labels change;
                                                     * both sides exchange this first so a version skew
                                                     * gives a clear "version mismatch" error          */
static constexpr int HANDSHAKE_TIMEOUT_S  = 30;    /* abort if peer stalls during the handshake       */
static constexpr int FRAME_TIMEOUT_S      = 30;    /* abort if a started frame does not complete in
                                                    * this many seconds (POSIX: SO_RCVTIMEO;
                                                    * Windows: GetTickCount64 timer in FD_READ)        */

/* Frame layout: [ seq(8) | ciphertext(488) | mac(16) ] = 512 bytes     */
/* Plaintext slot: [ len(2) | message(<=486) | zero padding ]           */

static_assert(FRAME_SZ == AD_SZ + CT_SZ + MAC_SZ);
static_assert(MAX_MSG == CT_SZ - 2);
static_assert(KEY == 32);
static_assert(NONCE_SZ == 24);
static_assert(MAC_SZ == 16);

/* ---- protocol function declarations ------------------------------------ */

/* Generate a fresh ephemeral X25519 keypair from the OS CSPRNG.
 * Ephemeral means one session only, never stored.  Past sessions cannot
 * be decrypted after the private key is wiped. */
void gen_keypair(uint8_t priv[KEY], uint8_t pub[KEY]);

/* Derive all session keys from the X25519 output and both public keys.
 * See protocol.c for the full IKM construction and derivation steps.
 * Returns 0, or -1 if dh is all-zero (small-subgroup / malicious key). */
[[nodiscard]] int session_init(session_t *s, int we_init,
                               const uint8_t self_priv[KEY],
                               const uint8_t self_pub[KEY],
                               const uint8_t peer_pub[KEY],
                               uint8_t sas_key_out[KEY]);

/* Wipe the entire session state at shutdown. */
void session_wipe(session_t *s);

/* Encrypt one message into a fixed 512-byte frame.
 *
 * next_chain is computed but the caller does NOT advance the chain until
 * the write succeeds -- "commit after successful send" keeps both sides
 * in sync even if a send fails midway. */
[[nodiscard]] int frame_build(const uint8_t chain[KEY], uint64_t seq,
                              const uint8_t *plain, uint16_t len,
                              uint8_t frame[FRAME_SZ], uint8_t next_chain[KEY]);

/* Decrypt and authenticate one 512-byte frame.
 *
 * Sequence number is checked first (cheap) to reject replays without any
 * crypto work.  The chain advances only after the MAC passes -- a forged
 * frame leaves session state untouched.
 *
 * Returns 0 on success (out and out_len filled), -1 on any failure. */
[[nodiscard]] int frame_open(session_t *s, const uint8_t frame[FRAME_SZ],
                             uint8_t *out, uint16_t *out_len);

/* Return 1 if s is a decimal integer in [1, 65535], 0 otherwise.
 * getaddrinfo silently accepts names, negatives, and out-of-range values;
 * this check ensures a typo produces a clear error message. */
[[nodiscard]] int validate_port(const char *s);

/* Replace non-printable bytes in a peer message with '.' before printing.
 *
 * An authenticated peer could embed ANSI / OSC escape sequences to rewrite
 * the screen, spoof the prompt, or access the clipboard on some terminals.
 * We allow printable ASCII (0x20-0x7E) and tab (0x09) only.
 * All other bytes -- including ESC (0x1B) -- become '.'. */
void sanitize_peer_text(uint8_t *buf, uint16_t len);

#endif /* SIMPLECIPHER_PROTOCOL_H */
