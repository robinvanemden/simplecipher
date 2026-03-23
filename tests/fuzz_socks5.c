/*
 * fuzz_socks5.c — libFuzzer harness for socks5_build_request().
 *
 * socks5_build_request parses two string inputs (hostname and port) and
 * builds a binary SOCKS5 CONNECT request.  This harness feeds arbitrary
 * bytes as host and port strings to find buffer overflows, off-by-one
 * errors, or crashes on malformed input.
 *
 * Build:
 *   clang -std=c23 -Isrc -Ilib -g -O1 -fsanitize=fuzzer,address,undefined \
 *     tests/fuzz_socks5.c src/platform.c src/crypto.c src/protocol.c \
 *     src/ratchet.c src/network.c src/tui.c src/tui_posix.c src/cli.c \
 *     src/cli_posix.c lib/monocypher.c -o fuzz_socks5
 *
 * Run:
 *   ./fuzz_socks5 [-max_total_time=60]
 */

#include "network.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    /* Split the fuzz input into host and port strings.
     * Use the first byte as the split point. */
    size_t split = data[0] % (size - 1);
    if (split == 0) split = 1;

    /* Create null-terminated copies */
    char host[257];
    char port[7];

    size_t host_len = split;
    if (host_len > sizeof host - 1) host_len = sizeof host - 1;
    memcpy(host, data + 1, host_len);
    host[host_len] = '\0';

    size_t port_len = size - 1 - split;
    if (port_len > sizeof port - 1) port_len = sizeof port - 1;
    memcpy(port, data + 1 + split, port_len);
    port[port_len] = '\0';

    /* socks5_build_request must never crash regardless of input */
    uint8_t buf[SOCKS5_REQ_MAX];
    (void)socks5_build_request(buf, sizeof buf, host, port);

    /* Also test with undersized buffer */
    uint8_t small[4];
    (void)socks5_build_request(small, sizeof small, host, port);

    /* Also test reply skip with arbitrary bytes */
    if (size >= 3) {
        (void)socks5_reply_skip(data[1], data[2]);
    }

    return 0;
}
