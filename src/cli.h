/*
 * cli.h — CLI (command-line interface) for SimpleCipher
 *
 * The CLI mode is the default, non-TUI interface: line-buffered input
 * from stdin, timestamped output to stdout.  It uses the same protocol
 * and crypto as TUI mode but without the box-drawing UI.
 *
 * On POSIX, the event loop uses poll() on both the socket and stdin.
 * On Windows, it uses WaitForMultipleObjects on a console input handle
 * and a Winsock event object.
 *
 * Read next: main.c (entry point that dispatches to CLI or TUI mode)
 */

#ifndef SIMPLECIPHER_CLI_H
#define SIMPLECIPHER_CLI_H

#include "protocol.h"
#include "network.h"

/* Write a formatted chat line to stdout without leaving plaintext in
 * libc's stdio buffer.  See cli.c for the implementation details. */
void secure_chat_print(const char *label, const char *msg);

/* CLI chat event loop.  Blocks until the session ends.
 * fd: the connected socket.  sess: the active crypto session.
 * cover: if non-zero, send encrypted dummy frames at random intervals
 *        to defeat Tor timing correlation attacks. */
void cli_chat_loop(socket_t fd, session_t *sess, int cover);

#if defined(_WIN32) || defined(_WIN64)
/* ---- Windows console / socket event helpers ----------------------------- */

/* Get the interactive console input handle and remember its current mode. */
int win_console_open(HANDLE *h_in, DWORD *old_mode);

/* Keep keyboard input, drop mouse/window events. */
void win_console_prepare(HANDLE h_in, DWORD old_mode);

/* Restore the console mode we inherited on startup. */
void win_console_restore(HANDLE h_in, DWORD old_mode);

/* Non-blocking send helper for the WSAEventSelect loop.
 *   0  -- full frame sent
 *   1  -- partial frame still pending (wait for FD_WRITE)
 *  -1  -- hard send failure */
int win_try_send(socket_t fd, const uint8_t *buf, size_t len, size_t *done);
#endif

#endif /* SIMPLECIPHER_CLI_H */
