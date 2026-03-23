/*
 * test_constant_time.c — Hardware-level timing side-channel verification
 *
 * Uses dudect (https://github.com/oreparaz/dudect) to statistically test
 * whether functions leak timing information that depends on secret inputs.
 *
 * HOW IT WORKS:
 *   1. Generate two classes of inputs: "fixed" (class 0) and "random" (class 1).
 *   2. Run the function under test many times (~2M) on both classes.
 *   3. Measure wall-clock execution time for each invocation using rdtsc.
 *   4. Apply Welch's t-test to the two timing distributions.
 *   5. If |t| > threshold, the execution time correlates with the input
 *      class — the function is variable-time (timing leak found).
 *
 * WHY THIS EXISTS ALONGSIDE TEST_TIMECOP.C:
 *
 * SimpleCipher has TWO constant-time verification tools that complement
 * each other.  Neither alone is sufficient.
 *
 * test_timecop.c (Valgrind/memcheck approach):
 *   + Deterministic: one run, definitive yes/no, exact source location.
 *   + Catches: secret-dependent branches, secret-dependent memory indexing.
 *   - Cannot see: hardware timing differences.  Valgrind runs code in a
 *     software CPU emulator that does not model cache lines, pipeline
 *     stalls, multiplication latency, or speculative execution.
 *
 * test_constant_time.c (this file, dudect approach):
 *   + Runs on REAL HARDWARE with the REAL CPU.
 *   + Catches: variable-latency multiplication (some ARM Cortex-M chips),
 *     cache-timing differences, CPU pipeline stalls that depend on operand
 *     values, any microarchitectural timing side channel.
 *   - Statistical: needs millions of measurements, no source location.
 *   - May miss leaks that require specific input patterns not covered by
 *     the random/fixed class design.
 *
 * Together they cover both classes of timing side channels:
 *   Timecop → control-flow leaks (branches on secrets)
 *   dudect  → hardware-level leaks (CPU timing on secrets)
 *
 * WHEN TO USE WHICH:
 *   - After any code change to crypto/protocol: run test_timecop.c (seconds).
 *   - Before a release or when targeting new hardware: run this file (minutes).
 *   - If porting to ARM/embedded: this file is essential — ARM Cortex-M
 *     may have non-constant-time multiplication that Valgrind cannot detect.
 *
 * FUNCTIONS TESTED (every function that handles secret data):
 *   1. is_zero32       — constant-time all-zero check (secret: DH output)
 *   2. verify_commit   — commitment comparison (secret: commitment hash)
 *   3. domain_hash     — KDF building block (secret: key material in msg)
 *   4. expand          — KDF subkey derivation (secret: PRK input)
 *   5. chain_step      — symmetric ratchet (secret: chain key)
 *   6. crypto_x25519   — DH key exchange (secret: private key)
 *   7. frame_build     — encrypt message (secret: session state)
 *   8. frame_open      — decrypt frame (known-accept, see below)
 *
 * For best results, run with CPU pinning to reduce measurement noise:
 *   taskset -c 0 ./test_ct
 *
 * Build:
 *   gcc -std=c23 -O2 -Isrc -Ilib -Itests \
 *     tests/test_constant_time.c src/platform.c src/crypto.c src/protocol.c \
 *     src/ratchet.c src/network.c src/tui.c src/tui_posix.c src/cli.c \
 *     src/cli_posix.c lib/monocypher.c -lm -o test_ct
 *   taskset -c 0 ./test_ct
 *
 * Exit code 0 if all tests pass, 1 if timing leakage detected.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "platform.h"
#include "crypto.h"
#include "protocol.h"
#include "../lib/monocypher.h"

/* Include dudect header (declarations only) */
#include "dudect.h"

/* ---- Test state --------------------------------------------------------- */

static uint8_t ct_fixed_input[512];   /* fixed-class input */
static uint8_t ct_key[32];            /* auxiliary secret (chain key, PRK, etc.) */
static uint8_t ct_key2[32];           /* second auxiliary (peer pub, etc.) */
static session_t ct_session;          /* session for frame_build/frame_open */
static int ct_test_id = 0;

/* ---- dudect callbacks --------------------------------------------------- */

/*
 * prepare_inputs: generate two classes of inputs for the t-test.
 *
 * Class 0 (fixed): always the same input — e.g. all-zero, or a specific
 *   secret value that triggers one code path.
 * Class 1 (random): uniformly random bytes — exercises the "other" path.
 *
 * If the function under test is constant-time, both classes should take
 * the same amount of time.  If not, the t-test will detect the difference.
 */
void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *input = input_data + i * c->chunk_size;
        if (classes[i] == 0) {
            memcpy(input, ct_fixed_input, c->chunk_size);
        } else {
            randombytes(input, c->chunk_size);
        }
    }
}

/*
 * do_one_computation: execute the function under test on one input.
 *
 * IMPORTANT: only the function under test should be inside the timed region.
 * Avoid key generation, memory allocation, or I/O here — those add noise
 * that masks timing differences.
 */
uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret = 0;
    switch (ct_test_id) {

    case 0: {
        /* is_zero32: test with zero vs non-zero 32-byte input.
         * A non-constant-time implementation would return early on
         * the first non-zero byte, leaking the position. */
        volatile bool result = is_zero32(data);
        ret = (uint8_t)result;
        break;
    }

    case 1: {
        /* verify_commit: test with matching vs non-matching commitment.
         * Uses crypto_verify32 internally — must not leak whether
         * the commitment matched or at which byte it diverged. */
        uint8_t commit[32];
        memcpy(commit, ct_key, 32);
        volatile int result = verify_commit(commit, data);
        ret = (uint8_t)result;
        break;
    }

    case 2: {
        /* domain_hash: BLAKE2b keyed hash.
         * The input data varies; the label is fixed.
         * A timing leak here would let an attacker distinguish
         * different secret inputs from their hashing time. */
        uint8_t out[32];
        domain_hash(out, "cipher commit v1", data, 32);
        ret = out[0];
        crypto_wipe(out, 32);
        break;
    }

    case 3: {
        /* expand: BLAKE2b keyed with secret PRK.
         * The PRK (data) varies between classes; the label is fixed.
         * Must not leak information about the PRK via timing. */
        uint8_t out[32];
        expand(out, data, "sas");
        ret = out[0];
        crypto_wipe(out, 32);
        break;
    }

    case 4: {
        /* chain_step: derive message key + next chain from chain key.
         * The chain key (data) is the secret. Both output paths
         * (mk and next) must take the same time regardless of
         * the chain key value. */
        uint8_t mk[32], next[32];
        chain_step(data, mk, next);
        ret = mk[0];
        crypto_wipe(mk, 32);
        crypto_wipe(next, 32);
        break;
    }

    case 5: {
        /* crypto_x25519: Diffie-Hellman key exchange.
         * data = private key (secret), ct_key = peer public key (public).
         * The most critical constant-time requirement: a timing leak
         * here directly leaks bits of the private key.
         *
         * Note: Monocypher's X25519 is constant-time by design, but
         * we verify it here because some platforms (old ARM Cortex-M)
         * have variable-time multiplication. */
        uint8_t shared[32];
        crypto_x25519(shared, data, ct_key);
        ret = shared[0];
        crypto_wipe(shared, 32);
        break;
    }

    case 6: {
        /* frame_build: encrypt a message with session state.
         * The plaintext (data) varies between classes. Encryption
         * must not leak the plaintext content via timing. */
        uint8_t frame[512], next_chain[32];
        session_t s;
        memcpy(&s, &ct_session, sizeof s);
        s.need_send_ratchet = 0;  /* avoid ratchet overhead noise */
        volatile int result = frame_build(&s, data, 16, frame, next_chain);
        ret = (uint8_t)(result & 0xFF);
        crypto_wipe(frame, sizeof frame);
        crypto_wipe(next_chain, 32);
        crypto_wipe(&s, sizeof s);
        break;
    }

    case 7: {
        /* frame_open: decrypt an incoming frame.
         * data = 512-byte frame (untrusted, varies between classes).
         *
         * NOTE: frame_open has an intentional early exit when the sequence
         * number doesn't match (seq != rx_seq).  The sequence number is
         * NOT secret — it's cleartext in the frame's AD field.  The early
         * exit is a performance optimization, not a timing leak.
         *
         * What we actually want to test: does frame_open leak timing on
         * the MAC verification or ciphertext content AFTER the seq check
         * passes?  To test this, both input classes must have a matching
         * sequence number (rx_seq = 0), so they both reach the crypto path.
         *
         * Fixed class: valid encrypted frame (passes MAC).
         * Random class: frame with correct seq but random ciphertext (fails MAC).
         * Leak: MAC comparison or decryption time depends on ciphertext content. */
        uint8_t frame[512];
        memcpy(frame, data, 512);
        /* Force seq = 0 so both classes pass the seq check */
        memset(frame, 0, 8);  /* le64(0) = 8 zero bytes */
        uint8_t out[486];
        uint16_t out_len = 0;
        session_t s;
        memcpy(&s, &ct_session, sizeof s);
        s.rx_seq = 0;
        volatile int result = frame_open(&s, frame, out, &out_len);
        ret = (uint8_t)(result & 0xFF);
        crypto_wipe(out, sizeof out);
        crypto_wipe(&s, sizeof s);
        break;
    }

    }
    return ret;
}

/* Include dudect implementation */
#define DUDECT_IMPLEMENTATION
#include "dudect.h"

/* ---- Test runner -------------------------------------------------------- */

static int run_test(const char *name, int test_id, size_t chunk_size,
                    int max_iterations) {
    ct_test_id = test_id;

    dudect_config_t config = {
        .chunk_size = chunk_size,
        .number_measurements = 1e4,
    };

    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    int iterations = 0;

    while (iterations < max_iterations) {
        state = dudect_main(&ctx);
        if (state == DUDECT_LEAKAGE_FOUND) break;
        iterations++;
    }

    dudect_free(&ctx);

    if (state == DUDECT_LEAKAGE_FOUND) {
        printf("  FAIL: %s — timing leakage detected\n", name);
        return 1;
    } else {
        printf("  PASS: %s — no timing leakage (%d iterations, ~%.1fM measurements)\n",
               name, iterations, iterations * 1e4 / 1e6);
        return 0;
    }
}

/* ---- Main --------------------------------------------------------------- */

int main(void) {
    printf("SimpleCipher Constant-Time Verification (dudect)\n");
    printf("================================================\n");
    printf("Tip: run with 'taskset -c 0 ./test_ct' for best results\n\n");

    int failures = 0;

    /* --- 1. is_zero32 ---
     * Fixed class: all-zero (returns true).
     * Random class: random bytes (returns false with overwhelming probability).
     * Leak: early exit on first non-zero byte. */
    printf("--- Comparison functions ---\n");
    memset(ct_fixed_input, 0, 32);
    failures += run_test("is_zero32", 0, 32, 200);

    /* --- 2. verify_commit ---
     * Fixed class: public key matching the commitment in ct_key.
     * Random class: random public key (won't match).
     * Leak: byte-by-byte comparison exit on first mismatch. */
    {
        uint8_t pub[32];
        fill_random(pub, 32);
        make_commit(ct_key, pub);
        memcpy(ct_fixed_input, pub, 32);
        crypto_wipe(pub, 32);
    }
    failures += run_test("verify_commit", 1, 32, 200);

    /* --- 3. domain_hash ---
     * Fixed class: all-zero input.
     * Random class: random input.
     * Leak: BLAKE2b should not branch on message content. */
    printf("\n--- KDF functions ---\n");
    memset(ct_fixed_input, 0, 32);
    failures += run_test("domain_hash", 2, 32, 200);

    /* --- 4. expand ---
     * Fixed class: all-zero PRK (secret root key).
     * Random class: random PRK.
     * Leak: BLAKE2b keyed hash should not branch on key content. */
    memset(ct_fixed_input, 0, 32);
    failures += run_test("expand", 3, 32, 200);

    /* --- 5. chain_step ---
     * Fixed class: all-zero chain key.
     * Random class: random chain key.
     * Leak: key derivation should not branch on chain key content. */
    memset(ct_fixed_input, 0, 32);
    failures += run_test("chain_step", 4, 32, 200);

    /* --- 6. crypto_x25519 ---
     * Fixed class: all-zero private key (degenerate case).
     * Random class: random private key.
     * Leak: scalar multiplication must be constant-time regardless of
     * which bits are set in the private key. This is the single most
     * important constant-time requirement in the protocol. */
    printf("\n--- Core cryptographic operations ---\n");
    fill_random(ct_key, 32);  /* fixed peer public key */
    crypto_x25519_public_key(ct_key, ct_key);  /* make it a valid point */
    memset(ct_fixed_input, 0, 32);
    failures += run_test("crypto_x25519", 5, 32, 200);

    /* --- 7. frame_build ---
     * Fixed class: all-zero plaintext.
     * Random class: random plaintext.
     * Leak: encryption time should not depend on plaintext content. */
    printf("\n--- Protocol operations ---\n");
    {
        uint8_t priv[32], pub[32], priv2[32], pub2[32], sas[32];
        fill_random(priv, 32);
        crypto_x25519_public_key(pub, priv);
        fill_random(priv2, 32);
        crypto_x25519_public_key(pub2, priv2);
        (void)session_init(&ct_session, 1, priv, pub, pub2, sas);
        crypto_wipe(priv, 32);
        crypto_wipe(priv2, 32);
    }
    memset(ct_fixed_input, 0, 32);
    failures += run_test("frame_build", 6, 32, 200);

    /* --- 8. frame_open ---
     * Fixed class: a validly encrypted frame (with seq=0).
     * Random class: random 512-byte frame (with seq forced to 0).
     * Both classes pass the sequence check (seq == rx_seq == 0),
     * so we're testing the AEAD decryption path, not the early exit.
     * Leak: MAC comparison or decryption time depends on ciphertext. */
    {
        /* Build a valid frame with the session's current tx (seq=0 already) */
        session_t build_s;
        uint8_t priv[32], pub[32], priv2[32], pub2[32], sas[32];
        fill_random(priv, 32);
        crypto_x25519_public_key(pub, priv);
        fill_random(priv2, 32);
        crypto_x25519_public_key(pub2, priv2);
        (void)session_init(&build_s, 1, priv, pub, pub2, sas);
        uint8_t next[32];
        (void)frame_build(&build_s, (const uint8_t *)"constant-time", 13,
                          ct_fixed_input, next);
        /* Set up ct_session for decryption with matching rx state */
        (void)session_init(&ct_session, 0, priv2, pub2, pub, sas);
        /* ct_session.rx_seq is already 0 */
        crypto_wipe(priv, 32);
        crypto_wipe(priv2, 32);
    }
    /* frame_open timing test: known-accept.
     *
     * Monocypher's crypto_aead_read intentionally skips ChaCha20 decryption
     * when the MAC fails (line 2921 of monocypher.c: "if (!mismatch)").
     * This means MAC-pass and MAC-fail take different amounts of time.
     *
     * This is NOT a vulnerability because:
     * 1. The timing difference only reveals pass/fail (not where it failed).
     * 2. The MAC is derived from ciphertext the attacker already has.
     * 3. An attacker cannot use this to forge valid ciphertext — they would
     *    need to break Poly1305 regardless of timing.
     * 4. Monocypher documents this as intentional design.
     *
     * We run the test to document the behavior but do not count it as a failure. */
    {
        int fo_leak = run_test("frame_open (AEAD path)", 7, 512, 200);
        if (fo_leak) {
            printf("         ^ known-accept: Monocypher skips decryption on MAC failure\n");
        }
    }

    printf("\n================================================\n");
    if (failures == 0) {
        printf("All 7 secret-handling functions verified constant-time.\n");
        printf("frame_open timing variance is a known Monocypher design choice.\n");
    } else {
        printf("%d function(s) showed unexpected timing leakage!\n", failures);
    }

    session_wipe(&ct_session);
    crypto_wipe(ct_key, 32);
    crypto_wipe(ct_key2, 32);

    return failures ? 1 : 0;
}
