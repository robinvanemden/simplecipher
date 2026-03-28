/*
 * fuzz_fingerprint.c — libFuzzer harness for fingerprint parsing.
 *
 * Tests the parse_fingerprint algorithm (reimplemented from jni_bridge.c)
 * and format_fingerprint with arbitrary inputs to find buffer overflows,
 * off-by-one errors, or crashes on malformed fingerprint strings.
 *
 * Build:
 *   clang -std=c23 -Isrc -Ilib -g -O1 -fsanitize=fuzzer,address,undefined \
 *     tests/fuzz_fingerprint.c src/platform.c src/crypto.c src/protocol.c \
 *     src/ratchet.c src/network.c src/tui.c src/tui_posix.c src/cli.c \
 *     src/cli_posix.c lib/monocypher.c -o fuzz_fingerprint
 *
 * Run:
 *   ./fuzz_fingerprint [-max_total_time=60]
 */

#include "crypto.h"
#include <string.h>
#include <stdint.h>

/* Reimplementation of jni_bridge.c parse_fingerprint — must match exactly. */
static int parse_fingerprint(uint8_t out[8], const char *s) {
    uint8_t buf[8];
    int     bi = 0;
    for (int i = 0; s[i] && bi < 8; i++) {
        char c = s[i];
        if (c == '-') continue;
        int hi, lo;
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else return -1;
        i++;
        if (!s[i]) return -1;
        c = s[i];
        if (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else return -1;
        buf[bi++] = (uint8_t)((hi << 4) | lo);
    }
    if (bi != 8) return -1;
    memcpy(out, buf, 8);
    return 0;
}

/* Reimplementation of verify.c fingerprint normalization logic. */
static void normalize_fingerprint(const char *input, char *out, int *out_len) {
    int oi = 0;
    for (int i = 0; input[i] && oi < 19; i++) {
        char c = input[i];
        if (c == '-') continue;
        if (c >= 'a' && c <= 'z') c -= 32;
        out[oi++] = c;
    }
    out[oi]  = '\0';
    *out_len = oi;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Create a null-terminated string from fuzz input */
    char   input[256];
    size_t len = size;
    if (len > sizeof input - 1) len = sizeof input - 1;
    memcpy(input, data, len);
    input[len] = '\0';

    /* Test 1: parse_fingerprint must not crash on any input */
    uint8_t parsed[8];
    int     result = parse_fingerprint(parsed, input);

    /* Test 2: if parse succeeds, verify round-trip consistency.
     * Format the parsed bytes back and re-parse — must match. */
    if (result == 0) {
        char formatted[20];
        snprintf(formatted, 20, "%02X%02X-%02X%02X-%02X%02X-%02X%02X", parsed[0], parsed[1], parsed[2], parsed[3],
                 parsed[4], parsed[5], parsed[6], parsed[7]);
        uint8_t reparsed[8];
        int     r2 = parse_fingerprint(reparsed, formatted);
        /* Re-parse must always succeed and produce identical bytes */
        if (r2 != 0 || memcmp(parsed, reparsed, 8) != 0) { __builtin_trap(); /* Round-trip failure = bug */ }
    }

    /* Test 3: normalize_fingerprint must not crash */
    char normalized[20];
    int  norm_len = 0;
    normalize_fingerprint(input, normalized, &norm_len);

    /* Test 4: format_fingerprint on random 32-byte "key" must not crash */
    if (size >= 32) {
        uint8_t pub[32];
        memcpy(pub, data, 32);
        char fp[20];
        format_fingerprint(fp, pub);

        /* Must always produce valid parseable output */
        uint8_t check[8];
        if (parse_fingerprint(check, fp) != 0) {
            __builtin_trap(); /* format_fingerprint produced unparseable output */
        }
    }

    /* Test 5: ct_compare must not crash with any inputs */
    if (size >= 16) {
        volatile int cmp = ct_compare(data, data + 8, 8);
        (void)cmp;
    }

    return 0;
}
