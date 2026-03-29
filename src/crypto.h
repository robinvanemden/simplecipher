/*
 * crypto.h — Cryptographic operations for SimpleCipher
 *
 * This module provides all the cryptographic building blocks used by
 * the SimpleCipher protocol:
 *
 *   - Domain-separated hashing (domain_hash) and key expansion (expand)
 *     built on BLAKE2b from Monocypher.
 *   - Nonce construction for XChaCha20-Poly1305.
 *   - The symmetric ratchet (chain_step) that provides forward secrecy:
 *     each message derives a one-time encryption key from the chain,
 *     then advances the chain.  Old keys are wiped immediately.
 *   - The commitment scheme (make_commit / verify_commit) that prevents
 *     a man-in-the-middle from brute-forcing the safety code.
 *   - Safety code formatting (format_sas) for human comparison.
 *   - Constant-time zero-check (is_zero32) to detect small-subgroup attacks.
 *
 * All cryptographic primitives (X25519, XChaCha20-Poly1305, BLAKE2b,
 * crypto_wipe) come from Monocypher, which is vendored in lib/.
 *
 * KEY DERIVATION TREE
 * ====================
 *
 *   X25519(self_priv, peer_pub) → dh_secret
 *                                    |
 *   IKM = dh_secret || init_pub || resp_pub || init_nonce || resp_nonce || version   (161 bytes, canonical order)
 *                                    |
 *   PRK = domain_hash("cipher x25519 sas root v1", IKM)
 *          |            |              |
 *       expand       expand         expand
 *       ("sas")     ("root")    ("init->resp" / "resp->init")
 *          |            |              |
 *        SAS key    root key      bootstrap tx/rx chains
 *      (32 bits     (persists     (per-message forward secrecy;
 *       for human    across DH     each message derives a one-time
 *       verify)      ratchets)     key then advances the chain)
 *
 * Read next: protocol.h (session key derivation and frame encryption)
 */

#ifndef SIMPLECIPHER_CRYPTO_H
#define SIMPLECIPHER_CRYPTO_H

#include "platform.h"
#include "../lib/monocypher.h"

/* =========================================================================
 * CONSTANTS
 *
 * All sizes in one place.  enum values are constant expressions in all C
 * standards, so they work in array sizes, static_assert, and case labels
 * on every compiler (including Clang 16 which lacks C23 constexpr).
 * ========================================================================= */
enum {
    KEY      = 32, /* bytes in any key or hash                          */
    NONCE_SZ = 24, /* XChaCha20 nonce size                              */
    MAC_SZ   = 16, /* Poly1305 MAC — proves ciphertext is untampered   */

    /* ---- formatted string sizes ----------------------------------------- */
    FINGERPRINT_STR_SZ = 20, /* "XXXX-XXXX-XXXX-XXXX" + NUL             */
    SAS_STR_SZ         = 20, /* "XXXX-XXXX" + NUL (oversized for safety) */
    PASSPHRASE_MAX     = 256
};

/* =========================================================================
 * SESSION STATE
 *
 * tx and rx are "chain keys": each message derives a fresh encryption key
 * from the current chain key and steps the chain forward.  Old chain keys
 * are wiped immediately.  This is forward secrecy -- a compromised chain
 * key today cannot decrypt past messages because those keys are gone.
 *
 * POST-COMPROMISE SECURITY (DH ratchet, see ratchet.h)
 *
 * The symmetric ratchet alone cannot recover if an attacker extracts a
 * chain key — the chain only goes forward deterministically.  The DH
 * ratchet (ratchet.c) fixes this: on each conversation direction switch,
 * fresh X25519 entropy is mixed into a root key, and new chain keys are
 * derived.  After one ratchet step, stolen keys are useless.
 *
 * Together, the symmetric ratchet + DH ratchet form a "Double Ratchet"
 * (the same model Signal uses): forward secrecy + post-compromise security.
 *
 * tx_seq / rx_seq are the expected sequence numbers.  Any frame with a
 * different sequence number is rejected as a replay or reorder.
 * ========================================================================= */
typedef struct {
    uint8_t  tx[KEY]; /* sending chain key              */
    uint8_t  rx[KEY]; /* receiving chain key            */
    uint64_t tx_seq;  /* next outgoing sequence number  */
    uint64_t rx_seq;  /* next expected incoming seq num */

    /* DH ratchet state — provides post-compromise security.
     *
     * The symmetric chain ratchet (chain_step in crypto.c) gives forward
     * secrecy: past message keys are wiped and unrecoverable.  But if an
     * attacker extracts the current chain key, they can derive all future
     * message keys in that chain — the chain only goes forward.
     *
     * The DH ratchet fixes this.  When the conversation direction switches
     * (Alice was receiving, now she sends), she generates a fresh X25519
     * keypair, computes a new shared secret with the peer's latest public
     * key, and mixes that into the root key to derive a new chain.  The
     * attacker's old chain key is now useless — the new chain depends on
     * a DH secret they don't have.
     *
     * root         — root key, used only to derive new chain keys.  Never
     *                used directly for encryption.
     * dh_priv/pub  — our current ratchet keypair (rotated on each send
     *                ratchet step).
     * peer_dh      — the peer's latest ratchet public key (updated when
     *                we receive a frame with FLAG_RATCHET set).
     * need_send_ratchet — set to 1 after receiving a message; when we
     *                next send, this triggers a DH ratchet step. */
    uint8_t root[KEY];
    uint8_t dh_priv[KEY];
    uint8_t dh_pub[KEY];
    uint8_t peer_dh[KEY];
    int     need_send_ratchet;

    /* Pre-computed ratchet state -- eliminates DH timing asymmetry.
     *
     * ratchet_prepare() pre-computes the full DH ratchet step eagerly:
     * first during ratchet_init() (session setup), then after every
     * received frame in frame_open().  Staged state exists from session
     * init onward.  ratchet_send() just copies pre-staged results.
     *
     * ratchet_prepared  -- 1 if staged fields below are valid.
     * staged_ratchet_ok -- 0 on success, -1 if DH produced all-zero output. */
    int     ratchet_prepared;
    uint8_t staged_dh_priv[KEY];
    uint8_t staged_dh_pub[KEY];
    uint8_t staged_root[KEY];
    uint8_t staged_tx[KEY];
    int     staged_ratchet_ok;

    /* No ratchet-stalling guard: DH ratchets trigger on direction switches,
     * so a one-directional burst of messages legitimately has no ratchet.
     * The symmetric chain ratchet still provides per-message forward secrecy;
     * the DH ratchet adds post-compromise security on the next direction switch. */
} session_t;

/* ---- crypto function declarations --------------------------------------- */

/* Constant-time all-zero check for 32 bytes.
 *
 * Used to detect the small-subgroup attack: a crafted public key (a
 * low-order curve point) forces the X25519 output to all-zeros regardless
 * of our private key, giving an attacker a known shared secret.
 *
 * The |= accumulator reads ALL 32 bytes unconditionally -- no early exit.
 * An early-exit loop would leak the position of the first non-zero byte
 * through timing differences. */
[[nodiscard]] bool is_zero32(const uint8_t x[32]);

/* Constant-time comparison of n bytes.  Returns 0 if equal, non-zero
 * if different.  The volatile accumulator prevents the compiler from
 * short-circuiting on the first difference, which would leak the
 * mismatch position through timing.
 *
 * Unlike crypto_verify16/32/64 (which require fixed-size buffers),
 * this works for any length — used for fingerprint comparison (8 bytes)
 * and anywhere else a variable-length constant-time check is needed. */
[[nodiscard]] int ct_compare(const uint8_t *a, const uint8_t *b, size_t n);

/* domain_hash: BLAKE2b keyed with a public domain label.
 *
 * Domain separation ensures that hashing the same data for different
 * protocol purposes produces unrelated outputs.  Each label ("cipher
 * commit v3", "cipher x25519 sas root v1", etc.) gives a distinct
 * output space so values cannot be confused or substituted across uses. */
void domain_hash(uint8_t out[32], const char *label, const uint8_t *msg, size_t msg_sz);

/* expand: BLAKE2b keyed with a secret PRK, labelled output.
 *
 * Derives one named 32-byte subkey from a root pseudo-random key (PRK).
 * Each label produces an independent output, so tx_chain, rx_chain, and
 * sas_key are unrelated even though they all come from the same PRK. */
void expand(uint8_t out[32], const uint8_t prk[32], const char *label);

/* Build the 24-byte XChaCha20 nonce from a sequence number.
 *
 * A nonce ("number used once") is a unique value that must never be reused
 * with the same key.  Reusing a nonce with the same key breaks XChaCha20's
 * security completely -- an attacker can XOR two ciphertexts to cancel out
 * the keystream and recover plaintexts.
 *
 * Our nonce is safe because the chain key changes with every message, so
 * even though the nonce bytes are predictable (just the seq number), the
 * key they pair with is always unique -- (key, nonce) is never reused.
 * Deriving the nonce from seq avoids storing it in the frame. */
void make_nonce(uint8_t nonce[NONCE_SZ], uint64_t seq);

/* Advance the symmetric ratchet one step.
 *
 * Derives two values from the current chain key:
 *   mk   -- one-time message key for this frame (wipe after AEAD)
 *   next -- replacement chain key (caller stores and wipes old chain)
 *
 * Per-message forward secrecy: mk for message N is independent of mk
 * for any other message, so compromising one key reveals nothing else. */
void chain_step(const uint8_t chain[32], uint8_t mk[32], uint8_t next[32]);

/* Hash pub||nonce to produce a 32-byte commitment.
 *
 * We send this commitment BEFORE revealing the actual key.  Once sent,
 * we cannot change our key without the peer noticing a mismatch.
 * Binding the session nonce prevents replay of a commitment from a
 * prior session.
 *
 * WHY THIS IS NECESSARY:
 * Without commitment, a man-in-the-middle (Mallory) could:
 *   1. Intercept Alice's key A.
 *   2. Wait to see Bob's key B.
 *   3. Search for a fake B' so SAS(DH(a, B'), A, B') matches Bob's SAS.
 *      Because the SAS is short and human-readable, this search succeeds
 *      in milliseconds.
 *
 * With commitment, Mallory must commit to her fake keys before she sees
 * A or B.  She cannot adapt after the fact, so the search attack fails. */
void make_commit(uint8_t commit[KEY], const uint8_t pub[KEY], const uint8_t nonce[KEY]);

/* Verify a revealed public key and nonce against a previously received
 * commitment.  Returns 1 if pub||nonce matches the commitment, 0 otherwise.
 * Uses constant-time comparison (consistent policy; costs nothing). */
[[nodiscard]] int verify_commit(const uint8_t commit[KEY], const uint8_t pub[KEY], const uint8_t nonce[KEY]);

/* Format 4 bytes of the SAS key as "AAAA-BBBB" for out-of-band comparison.
 *
 * 32 bits is sufficient because commitment prevents brute-forcing: Mallory
 * cannot search for a matching code after committing.  The hex format reads
 * clearly over a voice call: "A-3-F-2 dash 9-1-B-C". */
void format_sas(char out[SAS_STR_SZ], const uint8_t key[KEY]);

/* Format a public key fingerprint as "XXXX-XXXX-XXXX-XXXX" (16 hex chars
 * with dashes).  Uses the first 8 bytes of BLAKE2b(pub) for 64-bit
 * fingerprint — sufficient for interactive verification since the commitment
 * scheme prevents brute-force search.
 *
 * The fingerprint can be shared out-of-band (paper, QR code, Signal message)
 * and verified with --peer-fingerprint to confirm peer identity without
 * relying solely on the SAS code. */
void format_fingerprint(char out[FINGERPRINT_STR_SZ], const uint8_t pub[KEY]);

/* =========================================================================
 * PERSISTENT IDENTITY KEYS
 *
 * Encrypt/decrypt an X25519 identity keypair to a file, protected by a
 * passphrase via Argon2id + XChaCha20-Poly1305.
 *
 * File format (88 bytes, no header):
 *   [ salt : 16 ][ nonce : 24 ][ encrypted_priv : 32 ][ mac : 16 ]
 *
 * The passphrase is stretched with Argon2id (100 MB, 3 passes) to make
 * brute-force expensive.  Wrong passphrase is detected by MAC failure.
 *
 * These functions are used by `simplecipher keygen` and `--identity`.
 * ========================================================================= */
enum {
    IDENTITY_SALT_SZ = 16,
    IDENTITY_FILE_SZ = IDENTITY_SALT_SZ + NONCE_SZ + KEY + MAC_SZ /* 88 */
};

static_assert(IDENTITY_FILE_SZ == 88);

/* Save an encrypted identity key to a file.  Returns 0 on success. */
[[nodiscard]] int identity_save(const char *path, const uint8_t priv[KEY], const char *pass, size_t pass_len);

/* Load and decrypt an identity key from a file.  Derives the public key.
 * Returns 0 on success, -1 on wrong passphrase or corrupt/missing file. */
[[nodiscard]] int identity_load(const char *path, uint8_t priv[KEY], uint8_t pub[KEY], const char *pass,
                                size_t pass_len);

#endif /* SIMPLECIPHER_CRYPTO_H */
