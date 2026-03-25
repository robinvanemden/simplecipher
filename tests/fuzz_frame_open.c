/*
 * fuzz_frame_open.c — libFuzzer harness for frame_open().
 *
 * frame_open() is the primary attack surface: it parses 512-byte frames
 * received from the network, checking sequence numbers, decrypting with
 * AEAD, and validating the inner length field.
 *
 * Build:
 *   clang -std=c23 -Isrc -Ilib -g -O1 -fsanitize=fuzzer,address,undefined \
 *     tests/fuzz_frame_open.c src/platform.c src/crypto.c src/protocol.c \
 *     src/ratchet.c src/network.c src/tui.c src/tui_posix.c src/cli.c \
 *     src/cli_posix.c lib/monocypher.c -o fuzz_frame_open
 *
 * Run:
 *   ./fuzz_frame_open [-max_total_time=60]
 */

#include "protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < FRAME_SZ) return 0;  /* need exactly one frame */

    /* Set up a session with a deterministic key so the fuzzer can explore
     * paths beyond the initial seq check.  We cycle through a few rx_seq
     * values so the fuzzer can discover the seq-match path. */
    /* Zero-init gives deterministic DH ratchet fields (dh_priv, dh_pub,
     * root all zero).  This is safe: frame_open will parse the flags
     * and may call ratchet_receive with zero dh_priv, which is
     * deterministic but harmless for fuzzing purposes. */
    session_t s;
    memset(&s, 0, sizeof s);

    /* Use the first bytes beyond the frame (if any) to seed session state,
     * giving the fuzzer more control over which code paths are reached. */
    if (size >= FRAME_SZ + KEY) {
        memcpy(s.rx, data + FRAME_SZ, KEY);
    } else {
        /* Fixed key — fuzzer still explores tamper/length paths */
        memset(s.rx, 0xAA, KEY);
    }

    /* Let the fuzzer control rx_seq via the frame's AD field so it can
     * match the sequence check and reach deeper code. */
    s.rx_seq = le64_load(data);

    uint8_t out[MAX_MSG + 1];
    uint16_t out_len = 0;

    /* frame_open must never crash regardless of input */
    (void)frame_open(&s, data, out, &out_len);

    return 0;
}
