/*
 * test_constant_time.c — Verify timing-sensitive functions run in constant time.
 *
 * Uses dudect (https://github.com/oreparaz/dudect) to statistically test
 * whether functions leak timing information that depends on secret inputs.
 *
 * How it works:
 *   1. Generate two classes of inputs: "fixed" (class 0) and "random" (class 1).
 *   2. Run the function under test many times on both classes.
 *   3. Apply Welch's t-test to the execution time distributions.
 *   4. If |t| > threshold, the function is variable-time (timing leak found).
 *
 * Functions tested:
 *   - is_zero32:     constant-time all-zero check
 *   - verify_commit: constant-time commitment verification
 *
 * Build:
 *   gcc -std=c23 -O2 -Isrc -Ilib -Itests \
 *     tests/test_constant_time.c src/platform.c src/crypto.c src/protocol.c \
 *     src/ratchet.c src/network.c src/tui.c src/tui_posix.c src/cli.c \
 *     src/cli_posix.c lib/monocypher.c -lm -o test_ct
 *   ./test_ct
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

/* Include dudect header (declarations only) */
#include "dudect.h"

/* ---- Test state --------------------------------------------------------- */

static uint8_t ct_fixed_input[512];
static uint8_t ct_key[32];
static int ct_test_id = 0;

/* ---- dudect callbacks --------------------------------------------------- */

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

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret = 0;
    switch (ct_test_id) {
    case 0: {
        /* is_zero32: check if 32-byte input is all-zero */
        volatile bool result = is_zero32(data);
        ret = (uint8_t)result;
        break;
    }
    case 1: {
        /* verify_commit: check if commitment matches public key */
        uint8_t commit[32];
        memcpy(commit, ct_key, 32);
        volatile int result = verify_commit(commit, data);
        ret = (uint8_t)result;
        break;
    }
    }
    return ret;
}

/* Include dudect implementation */
#define DUDECT_IMPLEMENTATION
#include "dudect.h"

/* ---- Main --------------------------------------------------------------- */

static int run_test(const char *name, int test_id, size_t chunk_size) {
    ct_test_id = test_id;

    dudect_config_t config = {
        .chunk_size = chunk_size,
        .number_measurements = 1e4,
    };

    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    int iterations = 0;
    int max_iterations = 300;

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
        printf("  PASS: %s — no timing leakage (%d iterations)\n", name, iterations);
        return 0;
    }
}

int main(void) {
    printf("SimpleCipher Constant-Time Verification (dudect)\n");
    printf("================================================\n\n");

    int failures = 0;

    /* Test 1: is_zero32 — fixed class is all zeros, random class is random */
    memset(ct_fixed_input, 0, 32);
    failures += run_test("is_zero32", 0, 32);

    /* Test 2: verify_commit — fixed class matches commitment, random doesn't */
    {
        uint8_t pub[32];
        fill_random(pub, 32);
        make_commit(ct_key, pub);
        memcpy(ct_fixed_input, pub, 32);
    }
    failures += run_test("verify_commit", 1, 32);

    printf("\n================================================\n");
    printf("Total: %d failed\n", failures);

    return failures ? 1 : 0;
}
