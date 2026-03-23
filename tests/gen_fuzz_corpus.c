/*
 * gen_fuzz_corpus.c — Generate seed corpus files for libFuzzer harnesses.
 *
 * Produces realistic inputs so fuzzers start from valid protocol states
 * instead of random bytes, dramatically improving early coverage.
 *
 * Build & run:
 *   gcc -std=c23 -Isrc -Ilib -o gen_fuzz_corpus tests/gen_fuzz_corpus.c \
 *       src/platform.c src/crypto.c src/protocol.c src/ratchet.c \
 *       src/network.c src/tui.c src/tui_posix.c src/cli.c src/cli_posix.c \
 *       lib/monocypher.c
 *   ./gen_fuzz_corpus tests/corpus
 *
 * Creates:
 *   tests/corpus/frame_open/   — valid and edge-case encrypted frames
 *   tests/corpus/sanitize/     — text with various byte patterns
 *   tests/corpus/validate_port/ — port strings (valid, invalid, edge cases)
 */

#include "platform.h"
#include "crypto.h"
#include "protocol.h"

#include <sys/stat.h>

static void mkdirs(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static void write_file(const char *dir, const char *name,
                        const void *data, size_t len) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return; }
    fwrite(data, 1, len, f);
    fclose(f);
}

static void gen_frame_open_corpus(const char *base) {
    char dir[512];
    snprintf(dir, sizeof dir, "%s/frame_open", base);
    mkdirs(dir);

    uint8_t priv[KEY], pub[KEY], priv2[KEY], pub2[KEY];
    gen_keypair(priv, pub);
    gen_keypair(priv2, pub2);

    session_t s;
    uint8_t sas[KEY];
    (void)session_init(&s, 1, priv, pub, pub2, sas);

    /* Seed 1: valid frame with short message (frame + chain key for fuzzer) */
    {
        const char *msg = "hello";
        uint8_t frame[FRAME_SZ], next[KEY];
        (void)frame_build(&s, (const uint8_t *)msg,
                          (uint16_t)strlen(msg), frame, next);

        /* fuzz_frame_open reads FRAME_SZ bytes + optional KEY bytes */
        uint8_t seed[FRAME_SZ + KEY];
        memcpy(seed, frame, FRAME_SZ);
        memcpy(seed + FRAME_SZ, s.tx, KEY);  /* matching chain key */
        write_file(dir, "valid_short", seed, sizeof seed);

        /* Also write frame-only (uses fixed 0xAA key path) */
        write_file(dir, "valid_short_nokey", frame, FRAME_SZ);

        memcpy(s.tx, next, KEY);
        s.tx_seq++;
    }

    /* Seed 2: valid frame with empty message */
    {
        uint8_t frame[FRAME_SZ], next[KEY];
        (void)frame_build(&s, (const uint8_t *)"", 0, frame, next);
        uint8_t seed[FRAME_SZ + KEY];
        memcpy(seed, frame, FRAME_SZ);
        memcpy(seed + FRAME_SZ, s.tx, KEY);
        write_file(dir, "valid_empty", seed, sizeof seed);
        memcpy(s.tx, next, KEY);
        s.tx_seq++;
    }

    /* Seed 3: valid frame with max-length message */
    {
        uint8_t msg[MAX_MSG];
        memset(msg, 'A', MAX_MSG);
        uint8_t frame[FRAME_SZ], next[KEY];
        (void)frame_build(&s, msg, MAX_MSG, frame, next);
        uint8_t seed[FRAME_SZ + KEY];
        memcpy(seed, frame, FRAME_SZ);
        memcpy(seed + FRAME_SZ, s.tx, KEY);
        write_file(dir, "valid_maxlen", seed, sizeof seed);
        memcpy(s.tx, next, KEY);
        s.tx_seq++;
    }

    /* Seed 4: all-zero frame (exercises early rejection paths) */
    {
        uint8_t frame[FRAME_SZ];
        memset(frame, 0, FRAME_SZ);
        write_file(dir, "all_zero", frame, FRAME_SZ);
    }

    /* Seed 5: all-0xFF frame */
    {
        uint8_t frame[FRAME_SZ];
        memset(frame, 0xFF, FRAME_SZ);
        write_file(dir, "all_ff", frame, FRAME_SZ);
    }

    /* Seed 6: valid frame after 10 chain steps (deep ratchet state) */
    {
        for (int i = 0; i < 10; i++) {
            uint8_t frame[FRAME_SZ], next[KEY];
            (void)frame_build(&s, (const uint8_t *)"x", 1, frame, next);
            memcpy(s.tx, next, KEY);
            s.tx_seq++;
        }
        uint8_t frame[FRAME_SZ], next[KEY];
        (void)frame_build(&s, (const uint8_t *)"deep chain", 10,
                    frame, next);
        uint8_t seed[FRAME_SZ + KEY];
        memcpy(seed, frame, FRAME_SZ);
        memcpy(seed + FRAME_SZ, s.tx, KEY);
        write_file(dir, "deep_chain", seed, sizeof seed);
    }

    session_wipe(&s);
    crypto_wipe(priv, sizeof priv);
    crypto_wipe(priv2, sizeof priv2);
}

static void gen_sanitize_corpus(const char *base) {
    char dir[512];
    snprintf(dir, sizeof dir, "%s/sanitize", base);
    mkdirs(dir);

    /* Printable ASCII */
    write_file(dir, "ascii", "Hello, World! 0123456789", 24);

    /* With tabs */
    write_file(dir, "tabs", "col1\tcol2\tcol3", 14);

    /* ANSI escape sequence (terminal injection attempt) */
    uint8_t ansi[] = "\x1B[2J\x1B[H\x1B]0;pwned\x07";
    write_file(dir, "ansi_escape", ansi, sizeof ansi - 1);

    /* All control characters 0x00-0x1F */
    uint8_t ctrl[32];
    for (int i = 0; i < 32; i++) ctrl[i] = (uint8_t)i;
    write_file(dir, "all_control", ctrl, 32);

    /* High bytes 0x80-0xFF (non-ASCII) */
    uint8_t high[128];
    for (int i = 0; i < 128; i++) high[i] = (uint8_t)(0x80 + i);
    write_file(dir, "high_bytes", high, 128);

    /* Mixed: printable + escape + high + null */
    uint8_t mixed[] = "OK\x1B[31mRED\x1B[0m\x80\xFF\x00tail";
    write_file(dir, "mixed", mixed, sizeof mixed - 1);

    /* Max-length message of all dots */
    uint8_t maxlen[MAX_MSG];
    memset(maxlen, '.', MAX_MSG);
    write_file(dir, "maxlen_dots", maxlen, MAX_MSG);

    /* Single byte edge cases */
    uint8_t b;
    b = 0x00; write_file(dir, "null_byte", &b, 1);
    b = 0x09; write_file(dir, "tab_byte", &b, 1);
    b = 0x1B; write_file(dir, "esc_byte", &b, 1);
    b = 0x1F; write_file(dir, "unit_sep", &b, 1);
    b = 0x20; write_file(dir, "space", &b, 1);
    b = 0x7E; write_file(dir, "tilde", &b, 1);
    b = 0x7F; write_file(dir, "del", &b, 1);
    b = 0x80; write_file(dir, "first_high", &b, 1);
}

static void gen_validate_port_corpus(const char *base) {
    char dir[512];
    snprintf(dir, sizeof dir, "%s/validate_port", base);
    mkdirs(dir);

    /* Valid ports */
    write_file(dir, "port_1", "1", 1);
    write_file(dir, "port_80", "80", 2);
    write_file(dir, "port_443", "443", 3);
    write_file(dir, "port_7777", "7777", 4);
    write_file(dir, "port_65535", "65535", 5);

    /* Invalid: out of range */
    write_file(dir, "port_0", "0", 1);
    write_file(dir, "port_65536", "65536", 5);
    write_file(dir, "port_neg1", "-1", 2);
    write_file(dir, "port_huge", "999999999999", 12);

    /* Invalid: non-numeric */
    write_file(dir, "alpha", "abc", 3);
    write_file(dir, "mixed_80a", "80a", 3);
    write_file(dir, "empty", "", 0);
    write_file(dir, "spaces", "  80  ", 6);
    write_file(dir, "plus_80", "+80", 3);
    write_file(dir, "hex_0x50", "0x50", 4);
    write_file(dir, "octal_0777", "0777", 4);

    /* Edge: long numeric strings */
    char long_num[256];
    memset(long_num, '9', 255);
    long_num[255] = '\0';
    write_file(dir, "long_nines", long_num, 255);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <output-dir>\n", argv[0]);
        return 1;
    }

    printf("Generating seed corpus in %s/\n", argv[1]);
    gen_frame_open_corpus(argv[1]);
    gen_sanitize_corpus(argv[1]);
    gen_validate_port_corpus(argv[1]);
    printf("Done.\n");
    return 0;
}
