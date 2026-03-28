/*
 * fuzz_validate_port.c — libFuzzer harness for validate_port().
 *
 * validate_port() parses user-supplied strings into port numbers [1,65535].
 * It must never crash on arbitrary input and must correctly reject
 * out-of-range, empty, or non-numeric strings.
 *
 * Build:
 *   clang -std=c23 -Isrc -Ilib -g -O1 -fsanitize=fuzzer,address,undefined \
 *     tests/fuzz_validate_port.c src/platform.c src/crypto.c src/protocol.c \
 *     src/network.c src/tui.c src/tui_posix.c src/cli.c src/cli_posix.c \
 *     lib/monocypher.c -o fuzz_validate_port
 *
 * Run:
 *   ./fuzz_validate_port [-max_total_time=60]
 */

#include "protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* validate_port expects a NUL-terminated string */
    if (size > 256) return 0; /* skip absurdly long inputs */

    char buf[257];
    memcpy(buf, data, size);
    buf[size] = '\0';

    /* Must never crash regardless of input */
    (void)validate_port(buf);

    /* Also test with nullptr */
    (void)validate_port(nullptr);

    return 0;
}
