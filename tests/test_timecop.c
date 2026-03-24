/*
 * test_timecop.c — Valgrind-based constant-time verification (Timecop approach)
 *
 * This test uses Valgrind's memcheck to detect secret-dependent branches.
 * The technique: mark secret data as "uninitialized" using Valgrind's
 * client request API, then run the function.  If any conditional branch
 * or memory index depends on the secret, Valgrind reports:
 *   "Conditional jump or move depends on uninitialised value(s)"
 *
 * This is the same approach as ctgrind (Adam Langley, 2010) and Timecop
 * (SUPERCOP), but using modern Valgrind's built-in VALGRIND_MAKE_MEM_UNDEFINED
 * macro — no custom Valgrind patch needed.
 *
 * WHY THIS COMPLEMENTS DUDECT:
 *
 * dudect (test_constant_time.c) uses statistical timing measurements to
 * detect leaks.  It catches hardware-level timing differences (cache,
 * CPU instruction latency) but needs millions of measurements and gives
 * no source location.
 *
 * This Valgrind test catches control-flow leaks deterministically in a
 * single run, with exact file:line output.  But it can't detect hardware
 * timing differences (it runs in Valgrind's software CPU model).
 *
 * Together they cover both classes of timing side channels.
 *
 * FUNCTIONS TESTED (every function that handles secret data):
 *   1. is_zero32       — must not branch on input bytes
 *   2. verify_commit   — must not branch on comparison result
 *   3. domain_hash     — must not branch on message content
 *   4. expand          — must not branch on PRK content
 *   5. chain_step      — must not branch on chain key content
 *   6. crypto_x25519   — must not branch on private key bits
 *   7. frame_build     — must not branch on plaintext content
 *   8. ct_compare      — must not branch on input byte values
 *
 * NOT TESTED: frame_open — has an intentional early exit on sequence
 * number mismatch (seq is not secret) and Monocypher's AEAD intentionally
 * skips decryption on MAC failure.  Both are documented design choices.
 *
 * BUILD AND RUN:
 *   gcc -std=c23 -g -O1 -Isrc -Ilib \
 *     tests/test_timecop.c src/platform.c src/crypto.c src/protocol.c \
 *     src/ratchet.c src/network.c src/tui.c src/tui_posix.c src/cli.c \
 *     src/cli_posix.c lib/monocypher.c -lm -o test_timecop
 *   valgrind --track-origins=yes ./test_timecop
 *
 * Expected output: "ERROR SUMMARY: 0 errors from 0 contexts"
 * Any "uninitialised value" error = timing leak found.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "platform.h"
#include "crypto.h"
#include "protocol.h"
#include "../lib/monocypher.h"

/* Valgrind client request macros.
 * VALGRIND_MAKE_MEM_UNDEFINED marks bytes as "uninitialized" in memcheck's
 * shadow memory.  Any branch or index depending on these bytes triggers
 * a Valgrind error.
 *
 * When NOT running under Valgrind, these are no-ops (zero overhead). */
#include <valgrind/memcheck.h>

/* Helper: mark a buffer as "secret" (uninitialized in Valgrind's view).
 * The data is actually initialized — we just tell Valgrind to treat it
 * as tainted so it can detect secret-dependent branches. */
static void poison(void *buf, size_t len) {
    (void)VALGRIND_MAKE_MEM_UNDEFINED(buf, len);
}

/* Helper: unmark a buffer (tell Valgrind it's safe to branch on again). */
static void unpoison(void *buf, size_t len) {
    (void)VALGRIND_MAKE_MEM_DEFINED(buf, len);
}

int main(void) {
    printf("SimpleCipher Timecop Constant-Time Verification\n");
    printf("================================================\n");
    printf("Run under: valgrind --track-origins=yes ./test_timecop\n");
    printf("Expected: ERROR SUMMARY: 0 errors from 0 contexts\n\n");

    /* --- 1. is_zero32 ---
     * Must not branch on any byte of the input.
     * A non-constant-time version would early-exit on the first non-zero byte. */
    printf("Testing is_zero32...\n");
    {
        uint8_t buf[32];
        fill_random(buf, 32);
        poison(buf, 32);           /* mark input as secret */
        volatile bool r = is_zero32(buf);
        (void)r;
        unpoison(buf, 32);
    }

    /* --- 2. verify_commit ---
     * Must not branch on whether the commitment matches.
     * Uses crypto_verify32 internally (constant-time comparison). */
    printf("Testing verify_commit...\n");
    {
        uint8_t pub[32], commit[32];
        fill_random(pub, 32);
        make_commit(commit, pub);
        poison(commit, 32);        /* mark commitment as secret */
        poison(pub, 32);           /* mark public key as secret */
        volatile int r = verify_commit(commit, pub);
        (void)r;
        unpoison(commit, 32);
        unpoison(pub, 32);
    }

    /* --- 3. domain_hash ---
     * Must not branch on the message content (secret key material). */
    printf("Testing domain_hash...\n");
    {
        uint8_t msg[32], out[32];
        fill_random(msg, 32);
        poison(msg, 32);           /* mark message as secret */
        domain_hash(out, "cipher commit v1", msg, 32);
        unpoison(msg, 32);
        unpoison(out, 32);        /* output is derived from secret but now public */
    }

    /* --- 4. expand ---
     * Must not branch on the PRK (pseudo-random key) content. */
    printf("Testing expand...\n");
    {
        uint8_t prk[32], out[32];
        fill_random(prk, 32);
        poison(prk, 32);           /* mark PRK as secret */
        expand(out, prk, "sas");
        unpoison(prk, 32);
        unpoison(out, 32);
    }

    /* --- 5. chain_step ---
     * Must not branch on the chain key content. */
    printf("Testing chain_step...\n");
    {
        uint8_t chain[32], mk[32], next[32];
        fill_random(chain, 32);
        poison(chain, 32);         /* mark chain key as secret */
        chain_step(chain, mk, next);
        unpoison(chain, 32);
        unpoison(mk, 32);
        unpoison(next, 32);
    }

    /* --- 6. crypto_x25519 ---
     * Must not branch on the private key bits.  This is the single most
     * critical constant-time requirement — a timing leak here directly
     * leaks the private key to a network observer. */
    printf("Testing crypto_x25519...\n");
    {
        uint8_t priv[32], pub[32], shared[32];
        fill_random(priv, 32);
        fill_random(pub, 32);
        crypto_x25519_public_key(pub, pub);  /* make it a valid point */
        poison(priv, 32);          /* mark private key as secret */
        crypto_x25519(shared, priv, pub);
        unpoison(priv, 32);
        unpoison(shared, 32);
    }

    /* --- 8. ct_compare ---
     * Must not branch on either input buffer's content.
     * A non-constant-time version would exit early on the first
     * differing byte, leaking the mismatch position. */
    printf("Testing ct_compare...\n");
    {
        uint8_t a[8], b[8];
        fill_random(a, 8);
        memcpy(b, a, 8);
        poison(a, 8);              /* mark both inputs as secret */
        poison(b, 8);
        volatile int r = ct_compare(a, b, 8);
        (void)r;
        unpoison(a, 8);
        unpoison(b, 8);
    }

    /* --- 7. frame_build ---
     * Must not branch on plaintext content.  The plaintext is the user's
     * message — timing differences would leak message content to a network
     * observer measuring encryption time. */
    printf("Testing frame_build...\n");
    {
        uint8_t priv_a[32], pub_a[32], priv_b[32], pub_b[32], sas[32];
        fill_random(priv_a, 32);
        crypto_x25519_public_key(pub_a, priv_a);
        fill_random(priv_b, 32);
        crypto_x25519_public_key(pub_b, priv_b);

        session_t s;
        (void)session_init(&s, 1, priv_a, pub_a, pub_b, sas);

        uint8_t msg[16] = "secret message!";
        poison(msg, 16);           /* mark plaintext as secret */

        uint8_t frame[512], next[32];
        (void)frame_build(&s, msg, 16, frame, next);

        unpoison(msg, 16);
        unpoison(frame, 512);
        unpoison(next, 32);

        session_wipe(&s);
        crypto_wipe(priv_a, 32);
        crypto_wipe(priv_b, 32);
    }

    printf("\nAll functions tested.\n");
    printf("Check Valgrind's ERROR SUMMARY above — 0 errors = constant-time.\n");

    return 0;
}
