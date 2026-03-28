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
 * Wire format (randomized padding defeats DPI fingerprinting):
 *   [ pad_len : 1 ][ frame : 512 ][ random_pad : 0-255 ]
 *   pad_len is a raw CSPRNG byte (uniform random, no detectable pattern).
 *   Total wire size per message varies from 513 to 768 bytes.
 *
 * Plaintext slot:
 *   Normal:  [ flags(1) | len(2) | message(≤485) | zero padding ]
 *   Ratchet: [ flags(1) | ratchet_pub(32) | len(2) | message(≤453) | zero padding ]
 *
 * flags bit 0 (FLAG_RATCHET): a 32-byte X25519 ratchet public key follows.
 * Reserved bits 1-7 must be zero; frames with reserved bits set are rejected.
 *
 * Session key derivation (see session_init in protocol.c):
 *   ikm      = dh_shared_secret || initiator_pub || responder_pub
 *              || initiator_nonce || responder_nonce
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

enum {
    FRAME_SZ         = 512,
    AD_SZ            = 8,
    CT_SZ            = FRAME_SZ - AD_SZ - MAC_SZ,
    HEADER_SZ        = 1,                     /* flags byte in plaintext slot  */
    MAX_MSG          = CT_SZ - 2 - HEADER_SZ, /* 485 bytes       */
    MAX_MSG_RATCHET  = MAX_MSG - KEY,         /* 453 bytes       */
    PROTOCOL_VERSION = 1,
    FRAME_TIMEOUT_S  = 30,
    /* Maximum consecutive frame_open failures before session teardown.
     *
     * frame_open does NOT mutate session state on failure (chain, seq, root
     * are all untouched), so the next legitimate frame still works.  This
     * tolerance prevents an active network attacker from killing a session
     * by injecting a single forged frame during an idle period.
     *
     * After MAX_AUTH_FAILURES consecutive failures with no valid frame in
     * between, the session is torn down — either the peer is misbehaving
     * or the TCP stream is permanently corrupted by injection. */
    MAX_AUTH_FAILURES          = 3,
    MAX_FRAMES_WITHOUT_RATCHET = 50,
    /* Wire padding: each chat frame is sent as [pad_len(1)][frame][random_pad].
     * pad_len is a raw CSPRNG byte — uniform random, no detectable pattern. */
    WIRE_HDR     = 1,                                  /* pad_len byte            */
    WIRE_PAD_MAX = 255,                                /* max random padding      */
    WIRE_MAX     = WIRE_HDR + FRAME_SZ + WIRE_PAD_MAX, /* 768 bytes   */

    /* ---- timing constants ------------------------------------------------ */
    POLL_INTERVAL_MS     = 250,    /* event loop poll/wait granularity        */
    SAS_TIMEOUT_MS       = 300000, /* 5-minute SAS verification deadline     */
    EXCHANGE_DEADLINE_MS = 15000,  /* per-round handshake deadline            */
    COVER_DELAY_MIN_MS   = 500,
    COVER_DELAY_MAX_MS   = 2500
};
static const uint8_t FLAG_RATCHET = 0x01; /* bit 0: ratchet key follows */

static_assert(FRAME_SZ == AD_SZ + CT_SZ + MAC_SZ);
static_assert(MAX_MSG == 485);
static_assert(MAX_MSG_RATCHET == 453);
static_assert(KEY == 32);
static_assert(NONCE_SZ == 24);
static_assert(MAC_SZ == 16);
static_assert(WIRE_MAX == 768);

/* ---- protocol function declarations ------------------------------------ */

/* Generate a fresh ephemeral X25519 keypair from the OS CSPRNG.
 * Ephemeral means one session only, never stored.  Past sessions cannot
 * be decrypted after the private key is wiped. */
void gen_keypair(uint8_t priv[KEY], uint8_t pub[KEY]);

/* Derive all session keys from the X25519 output, both public keys, and
 * both session nonces.  Session nonces ensure unique keys even when the
 * same identity keypair is reused across sessions.
 * See protocol.c for the full IKM construction and derivation steps.
 * Returns 0, or -1 if dh is all-zero (small-subgroup / malicious key). */
[[nodiscard]] int session_init(session_t *s, int we_init, const uint8_t self_priv[KEY], const uint8_t self_pub[KEY],
                               const uint8_t peer_pub[KEY], const uint8_t self_nonce[KEY],
                               const uint8_t peer_nonce[KEY], uint8_t sas_key_out[KEY]);

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
[[nodiscard]] int frame_build(session_t *s, const uint8_t *plain, uint16_t len, uint8_t frame[FRAME_SZ],
                              uint8_t next_chain[KEY]);

/* Decrypt and authenticate one 512-byte frame.
 *
 * Sequence number is checked first (cheap) to reject replays without any
 * crypto work.  The chain advances only after the MAC passes -- a forged
 * frame leaves session state untouched.
 *
 * Returns 0 on success (out and out_len filled), -1 on auth/sequence
 * failure (tolerable up to MAX_AUTH_FAILURES), or -2 on ratchet DH
 * failure (session-fatal — callers must tear down immediately). */
[[nodiscard]] int frame_open(session_t *s, const uint8_t frame[FRAME_SZ], uint8_t *out, uint16_t *out_len);

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

/* Random delay in [500, 2500] ms for cover traffic scheduling.
 * Uses the OS CSPRNG to prevent the interval itself from becoming a
 * fingerprint.  The range provides ~0.4-2 frames/sec average throughput
 * — enough to mask real message timing over Tor without excessive
 * bandwidth (~170-500 bytes/sec overhead). */
unsigned cover_delay_ms(void);

#endif /* SIMPLECIPHER_PROTOCOL_H */
