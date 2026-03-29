/*
 * fuzz_identity_load.c — libFuzzer harness for identity_load().
 *
 * identity_load() reads a passphrase-protected identity key file,
 * derives an encryption key via Argon2id, and decrypts the private key.
 * It must handle truncated, corrupt, and adversarially crafted files
 * without crashing or leaking memory.
 *
 * Build:
 *   clang -std=c23 -Isrc -Ilib -g -O1 -fsanitize=fuzzer,address,undefined \
 *     tests/fuzz_identity_load.c src/platform.c src/crypto.c src/protocol.c \
 *     src/ratchet.c src/network.c src/tui.c src/tui_posix.c src/cli.c \
 *     src/cli_posix.c lib/monocypher.c -lm -o fuzz_identity_load
 *
 * Run:
 *   ./fuzz_identity_load [-max_total_time=60]
 */

#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Split fuzz input: first byte = passphrase length (0-255),
     * next pass_len bytes = passphrase, remainder = file content. */
    if (size < 1) return 0;

    size_t pass_len = data[0];
    data++;
    size--;
    if (pass_len > size) pass_len = size;

    const uint8_t *pass_data = data;
    const uint8_t *file_data = data + pass_len;
    size_t         file_sz   = size - pass_len;

    /* Write file content to a temporary file */
    char tmp[] = "/tmp/fuzz_id_XXXXXX";
    int  fd    = mkstemp(tmp);
    if (fd < 0) return 0;

    if (file_sz > 0) {
        ssize_t wr = write(fd, file_data, file_sz);
        (void)wr;
    }
    close(fd);

    /* identity_load must never crash regardless of file content or
     * passphrase.  We use a trivially short Argon2 config in the real
     * code (100 MB), so this will be slow per iteration — keep corpus
     * small or use a reduced-cost build for fuzzing. */
    uint8_t priv[32], pub[32];
    (void)identity_load(tmp, priv, pub, (const char *)pass_data, pass_len);

    /* Clean up */
    crypto_wipe(priv, sizeof priv);
    crypto_wipe(pub, sizeof pub);
    unlink(tmp);

    return 0;
}
