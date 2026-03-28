/*
 * fuzz_sanitize.c — libFuzzer harness for sanitize_peer_text().
 *
 * sanitize_peer_text() processes decrypted peer messages before display.
 * It must replace all non-printable / non-ASCII bytes with '.' and never
 * read or write out of bounds.
 *
 * Build:
 *   clang -std=c23 -Isrc -Ilib -g -O1 -fsanitize=fuzzer,address,undefined \
 *     tests/fuzz_sanitize.c src/platform.c src/crypto.c src/protocol.c \
 *     src/network.c src/tui.c src/tui_posix.c src/cli.c src/cli_posix.c \
 *     lib/monocypher.c -o fuzz_sanitize
 *
 * Run:
 *   ./fuzz_sanitize [-max_total_time=60]
 */

#include "protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > MAX_MSG) return 0;

    /* Work on a mutable copy */
    uint8_t buf[MAX_MSG];
    memcpy(buf, data, size);

    sanitize_peer_text(buf, (uint16_t)size);

    /* Post-condition: every byte must be printable ASCII (0x20-0x7E) */
    for (uint16_t i = 0; i < (uint16_t)size; i++) {
        if (buf[i] < 0x20 || buf[i] > 0x7E) __builtin_trap(); /* sanitize missed a byte */
    }

    return 0;
}
