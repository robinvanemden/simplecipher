/*
 * verify.h — Human-facing identity verification for SimpleCipher
 *
 * This module handles all interactive identity verification steps:
 *
 *   - Passphrase input with echo disabled (POSIX termios / Windows _getch)
 *   - Persistent identity key generation (keygen subcommand)
 *   - Peer fingerprint verification against a pre-shared value
 *   - CLI-mode SAS (Short Authentication String) ceremony with
 *     peer-disconnect detection, timeout, and constant-time comparison
 *
 * These functions were extracted from main.c to keep the entry point
 * focused on session lifecycle orchestration.
 *
 * Read next: main.c (session lifecycle that calls these functions)
 */

#ifndef SIMPLECIPHER_VERIFY_H
#define SIMPLECIPHER_VERIFY_H

#include "protocol.h"
#include "network.h"

/* Read a passphrase from /dev/tty (POSIX) or console (Windows) with
 * echo disabled.  Returns length, or -1 on error.  Caller must wipe buf. */
int read_passphrase(const char *prompt, char *buf, size_t bufsz);

/* Strip dashes and uppercase a hex string for comparison.
 * Returns chars written to out (excluding NUL).  Caller must wipe out. */
int normalize_hex(const char *in, char *out, size_t out_sz);

/* Handle the keygen subcommand: generate a passphrase-protected identity key.
 * Returns EXIT_OK on success, EXIT_USAGE or EXIT_INTERNAL on failure. */
int keygen_main(const char *path);

/* Verify peer's public key fingerprint against expected value.
 * Returns 0 if OK (or no fingerprint expected), -1 on mismatch. */
int verify_peer_fingerprint(const uint8_t peer_pub[KEY], const char *expected, int tui_mode);

/* CLI-mode SAS verification: display the safety code box, read user input
 * with peer-disconnect detection, compare typed code against expected.
 * Returns EXIT_OK on match, EXIT_MITM on mismatch, EXIT_ABORT on timeout/cancel. */
int cli_sas_verify(const char *sas, socket_t fd);

#endif /* SIMPLECIPHER_VERIFY_H */
