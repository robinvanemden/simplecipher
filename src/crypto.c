/*
 * crypto.c — Cryptographic operations implementation for SimpleCipher
 *
 * Implements the domain-separated hashing, key expansion, nonce
 * construction, symmetric ratchet, commitment scheme, and safety code
 * formatting declared in crypto.h.
 *
 * All crypto primitives (BLAKE2b, X25519, crypto_wipe) come from
 * Monocypher (lib/monocypher.c).
 */

#include "crypto.h"

/* Constant-time all-zero check for 32 bytes.
 *
 * Used to detect the small-subgroup attack: a crafted public key (a
 * low-order curve point) forces the X25519 output to all-zeros regardless
 * of our private key, giving an attacker a known shared secret.
 *
 * The |= accumulator reads ALL 32 bytes unconditionally -- no early exit.
 * An early-exit loop would leak the position of the first non-zero byte
 * through timing differences. */
[[nodiscard]] bool is_zero32(const uint8_t x[32]){
    uint8_t acc = 0;
    int i;
    for (i = 0; i < 32; i++) acc |= x[i];
    return acc == 0;
}

/* Constant-time comparison of n bytes. */
[[nodiscard]] int ct_compare(const uint8_t *a, const uint8_t *b, size_t n){
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff;
}

/* domain_hash: BLAKE2b keyed with a public domain label.
 *
 * Domain separation ensures that hashing the same data for different
 * protocol purposes produces unrelated outputs.  Each label ("cipher
 * commit v1", "cipher x25519 sas root v1", etc.) gives a distinct
 * output space so values cannot be confused or substituted across uses. */
void domain_hash(uint8_t out[32], const char *label,
                 const uint8_t *msg, size_t msg_sz){
    crypto_blake2b_keyed(out, 32,
                         (const uint8_t*)label, strlen(label),
                         msg, msg_sz);
}

/* expand: BLAKE2b keyed with a secret PRK, labelled output.
 *
 * Derives one named 32-byte subkey from a root pseudo-random key (PRK).
 * Each label produces an independent output, so tx_chain, rx_chain, and
 * sas_key are unrelated even though they all come from the same PRK. */
void expand(uint8_t out[32], const uint8_t prk[32], const char *label){
    crypto_blake2b_keyed(out, 32, prk, 32,
                         (const uint8_t*)label, strlen(label));
}

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
void make_nonce(uint8_t nonce[NONCE_SZ], uint64_t seq){
    memset(nonce, 0, NONCE_SZ);
    le64_store(nonce, seq);
}

/* Advance the symmetric ratchet one step.
 *
 * Derives two values from the current chain key:
 *   mk   -- one-time message key for this frame (wipe after AEAD)
 *   next -- replacement chain key (caller stores and wipes old chain)
 *
 * Per-message forward secrecy: mk for message N is independent of mk
 * for any other message, so compromising one key reveals nothing else. */
void chain_step(const uint8_t chain[32], uint8_t mk[32], uint8_t next[32]){
    expand(mk,   chain, "mk");
    expand(next, chain, "chain");
}

/* ---- commitment scheme -------------------------------------------------- */

/* Hash our public key to produce a 32-byte commitment.
 *
 * We send this commitment BEFORE revealing the actual key.  Once sent,
 * we cannot change our key without the peer noticing a mismatch.
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
void make_commit(uint8_t commit[KEY], const uint8_t pub[KEY]){
    domain_hash(commit, "cipher commit v1", pub, KEY);
}

/* Verify a revealed public key against a previously received commitment.
 * Returns 1 if the key matches the commitment, 0 otherwise.
 * Uses constant-time comparison (consistent policy; costs nothing). */
[[nodiscard]] int verify_commit(const uint8_t commit[KEY], const uint8_t pub[KEY]){
    uint8_t expected[KEY];
    int ok;
    domain_hash(expected, "cipher commit v1", pub, KEY);
    ok = (crypto_verify32(expected, commit) == 0);
    crypto_wipe(expected, sizeof expected);
    return ok;
}

/* Format 4 bytes of the SAS key as "AAAA-BBBB" for out-of-band comparison.
 *
 * 32 bits is sufficient because commitment prevents brute-forcing: Mallory
 * cannot search for a matching code after committing.  The hex format reads
 * clearly over a voice call: "A-3-F-2 dash 9-1-B-C". */
void format_sas(char out[20], const uint8_t key[KEY]){
    snprintf(out, 20, "%02X%02X-%02X%02X",
             key[0], key[1], key[2], key[3]);
}

/* Format a public key fingerprint as "XXXX-XXXX-XXXX-XXXX" (16 hex chars).
 *
 * Hashes the public key with a distinct domain label, then formats the first
 * 8 bytes (64 bits) as four dash-separated groups of 4 hex digits.  64 bits
 * is sufficient for interactive verification: with the commitment scheme in
 * place, an attacker cannot brute-force a matching fingerprint.
 *
 * The fingerprint lets users verify peer identity out-of-band (paper, QR code,
 * Signal) before the session starts, adding a second layer of trust beyond
 * the in-session SAS code. */
void format_fingerprint(char out[20], const uint8_t pub[KEY]){
    uint8_t hash[32];
    domain_hash(hash, "cipher fingerprint v2", pub, KEY);
    snprintf(out, 20, "%02X%02X-%02X%02X-%02X%02X-%02X%02X",
             hash[0], hash[1], hash[2], hash[3],
             hash[4], hash[5], hash[6], hash[7]);
    crypto_wipe(hash, sizeof hash);
}
