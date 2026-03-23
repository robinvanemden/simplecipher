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
 * Plaintext slot (v2):
 *   Normal:  [ flags(1) | len(2) | message(≤485) | zero padding ]
 *   Ratchet: [ flags(1) | ratchet_pub(32) | len(2) | message(≤453) | zero padding ]
 *
 * flags bit 0 (FLAG_RATCHET): a 32-byte X25519 ratchet public key follows.
 * Reserved bits 1-7 must be zero; frames with reserved bits set are rejected.
 *
 * Session key derivation (see session_init in protocol.c):
 *   ikm      = dh_shared_secret || initiator_pub || responder_pub
 *   prk      = domain_hash("cipher x25519 sas root v1", ikm)
 *   sas_key  = expand(prk, "sas")
 *   root_key = expand(prk, "root")
 *   bootstrap_chain = expand(root_key, "resp->init")
 *   ... then ratchet_init derives the DH-ratcheted chains from root_key
 *
 * The commit-after-send pattern ensures both sides stay in sync:
 * the chain is advanced only after a successful network write.
 *
 * Read next: ratchet.h (DH ratchet), network.h (TCP I/O), crypto.h (primitives)
 */

#ifndef SIMPLECIPHER_PROTOCOL_H
#define SIMPLECIPHER_PROTOCOL_H

#include "crypto.h"

/* ---- frame constants ---------------------------------------------------- */

static constexpr int FRAME_SZ             = 512;
static constexpr int AD_SZ                = 8;
static constexpr int CT_SZ                = FRAME_SZ - AD_SZ - MAC_SZ;
static constexpr int HEADER_SZ            = 1;     /* flags byte in plaintext slot  */
static constexpr int MAX_MSG              = CT_SZ - 2 - HEADER_SZ;  /* 485 bytes    */
static constexpr int MAX_MSG_RATCHET      = MAX_MSG - KEY;           /* 453 bytes    */
static constexpr uint8_t FLAG_RATCHET     = 0x01;  /* bit 0: ratchet key follows    */
static constexpr int PROTOCOL_VERSION     = 2;
static constexpr int HANDSHAKE_TIMEOUT_S  = 30;
static constexpr int FRAME_TIMEOUT_S      = 30;

static_assert(FRAME_SZ == AD_SZ + CT_SZ + MAC_SZ);
static_assert(MAX_MSG == 485);
static_assert(MAX_MSG_RATCHET == 453);
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
 * Calls ratchet_send() to check if a DH ratchet step is needed.  If so,
 * the frame's flags byte is set to FLAG_RATCHET and the sender's new
 * ratchet public key is included in the plaintext slot.
 *
 * next_chain is computed but the caller does NOT advance the chain until
 * the write succeeds -- "commit after successful send" keeps both sides
 * in sync even if a send fails midway.
 *
 * Note: ratchet state (root, dh_priv, dh_pub, tx) is mutated inside
 * ratchet_send before the frame is built.  If the subsequent write fails,
 * the session is inconsistent -- this is acceptable because any I/O
 * failure is session-fatal in SimpleCipher. */
[[nodiscard]] int frame_build(session_t *s,
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
 * Only printable ASCII (0x20-0x7E) passes through.
 * All other bytes -- including ESC (0x1B) and tab (0x09) -- become '.'. */
void sanitize_peer_text(uint8_t *buf, uint16_t len);

#endif /* SIMPLECIPHER_PROTOCOL_H */
