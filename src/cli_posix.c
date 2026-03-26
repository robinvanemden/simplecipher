/*
 * cli_posix.c — POSIX CLI chat event loop for SimpleCipher
 *
 * This file is compiled only on POSIX systems (Linux, macOS, BSD).
 * It provides cli_chat_loop() using poll() on the socket and stdin.
 *
 * RAW MODE
 * ========
 * Unlike the original cooked-mode version, this loop switches the terminal
 * to raw mode (when stdin is a TTY) so it can:
 *   - Show a "> " prompt so the user knows where to type
 *   - Handle peer messages arriving mid-typing without corrupting the display
 *     (clear the input line, print the message, then redraw prompt + partial input)
 *   - Handle backspace, Ctrl+C, Ctrl+D as individual keystrokes
 *
 * This mirrors what the Windows CLI (cli_win.c) already does with
 * ReadConsoleInputA and manual line buffering.
 *
 * When stdin is NOT a TTY (e.g. redirected from a file or pipe), we fall
 * back to cooked-mode behaviour: no prompt, no raw termios, line-buffered
 * reads.  This keeps scripted/piped usage working.
 *
 * The Windows equivalent lives in cli_win.c with the same function name;
 * only one file is compiled per platform.
 */

#include "cli.h"

#ifndef _WIN32

#    include <termios.h>

/* ---- Raw-mode terminal management ----------------------------------------
 *
 * We save the original termios settings before switching to raw mode,
 * then restore them via atexit() so the terminal is never left broken --
 * even if the process exits abnormally (but not on SIGKILL/SIGABRT).
 *
 * Flags cleared for raw mode:
 *   ECHO    -- don't echo typed characters (we echo them ourselves)
 *   ICANON  -- don't buffer until Enter (deliver each byte immediately)
 *   ISIG    -- don't generate SIGINT/SIGTSTP on Ctrl+C/Ctrl+Z
 *              (we handle Ctrl+C as byte 0x03 in the read loop)
 *   IXON    -- don't intercept Ctrl+S/Ctrl+Q for flow control
 *   ICRNL   -- don't translate \r to \n (we check for both explicitly)
 *
 * VMIN=0, VTIME=0: non-blocking reads -- read() returns immediately with
 * 0 bytes if nothing is available, so poll() controls all blocking. */

static struct termios cli_orig_termios;
static int            cli_termios_saved = 0;

static void cli_restore_term(void) {
    if (cli_termios_saved) tcsetattr(STDIN_FILENO, TCSAFLUSH, &cli_orig_termios);
}

static int cli_init_raw_mode(void) {
    struct termios raw;

    /* Only enter raw mode if stdin is actually a terminal.
     * If stdin is a pipe or file, isatty() returns 0 and we stay in
     * cooked mode so piped input still works normally. */
    if (!isatty(STDIN_FILENO)) return 0;

    if (tcgetattr(STDIN_FILENO, &cli_orig_termios) != 0) return 0;

    cli_termios_saved = 1;
    atexit(cli_restore_term);

    raw = cli_orig_termios;
    raw.c_lflag &= ~(unsigned)(ECHO | ICANON | ISIG);
    raw.c_iflag &= ~(unsigned)(IXON | ICRNL);
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

    return 1; /* raw mode active */
}

/* ---- Prompt / line-drawing helpers (raw mode only) ----------------------
 *
 * These use write() directly to STDOUT_FILENO to avoid libc's stdio
 * buffer.  This is consistent with secure_chat_print() and prevents
 * plaintext from lingering in a 4 KB internal buffer. */

/* Erase the current "> partial_input" from the screen.
 * Writes: \r, (line_len+2) spaces to overwrite, then \r to return. */
static void cli_clear_input_line(size_t line_len) {
    char   buf[MAX_MSG + 4];
    size_t total = line_len + 2; /* 2 for "> " prefix */
    size_t i;

    buf[0] = '\r';
    for (i = 0; i < total && i + 1 < sizeof buf - 1; i++) buf[i + 1] = ' ';
    buf[i + 1] = '\r';

    ssize_t r;
    do { r = write(STDOUT_FILENO, buf, i + 2); } while (r < 0 && errno == EINTR);
}

/* Redraw "> partial_input" at the current cursor position. */
static void cli_redraw_input(const char *line, size_t line_len) {
    /* Build "> " + line content in one write to avoid flicker. */
    char buf[MAX_MSG + 4];
    buf[0] = '>';
    buf[1] = ' ';
    if (line_len > 0) memcpy(buf + 2, line, line_len);
    size_t total = 2 + line_len;

    ssize_t r;
    do { r = write(STDOUT_FILENO, buf, total); } while (r < 0 && errno == EINTR);
}

/* ---- Raw-mode chat loop -------------------------------------------------
 *
 * Reads one byte at a time from the terminal, manages its own line buffer,
 * and handles peer messages by clearing/redrawing the input line.
 *
 * This is the POSIX equivalent of the Windows raw key-event loop in
 * cli_win.c, adapted to use termios + poll() instead of
 * ReadConsoleInputA + WaitForMultipleObjects. */
static void cli_chat_loop_raw(socket_t fd, session_t *sess, int cover) {
    char     line[MAX_MSG + 1];
    size_t   line_len = 0;
    uint8_t  frame[FRAME_SZ];
    uint8_t  next_tx[KEY];
    uint8_t  plain[MAX_MSG + 1];
    uint16_t plen;
    int      auth_fails = 0;
    uint64_t next_cover = cover ? monotonic_ms() + (uint64_t)cover_delay_ms() : 0;

    memset(line, 0, sizeof line);

    /* Show initial prompt. */
    cli_redraw_input(line, line_len);

    while (g_running) {
        struct pollfd fds[2];
        int           ready;

        fds[0].fd     = fd;
        fds[0].events = POLLIN;
        fds[1].fd     = STDIN_FILENO;
        fds[1].events = POLLIN;

        int timeout = 250;
        if (cover) {
            int64_t remain = (int64_t)(next_cover - monotonic_ms());
            if (remain <= 0) timeout = 0;
            else if (remain < timeout) timeout = (int)remain;
        }

        ready = poll(fds, 2, timeout);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* ----- Incoming encrypted frame from peer -----
         *
         * Before printing, we erase the user's partial input line so the
         * peer message appears cleanly on its own line.  After printing,
         * we redraw the prompt and whatever the user had typed so far. */
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            if (read_exact_dl(fd, frame, FRAME_SZ, monotonic_ms() + (uint64_t)FRAME_TIMEOUT_S * 1000) != 0) {
                cli_clear_input_line(line_len);
                {
                    const char *msg = "\n  [peer disconnected]\n";
                    ssize_t     r;
                    do { r = write(STDOUT_FILENO, msg, strlen(msg)); } while (r < 0 && errno == EINTR);
                }
                break;
            }
            plen      = 0;
            int fo_rc = frame_open(sess, frame, plain, &plen);
            if (fo_rc != 0) {
                crypto_wipe(plain, sizeof plain);
                crypto_wipe(frame, sizeof frame);
                if (fo_rc == -2 || ++auth_fails >= MAX_AUTH_FAILURES) {
                    cli_clear_input_line(line_len);
                    {
                        const char *msg = "[session error: authentication or sequence failure]\n";
                        ssize_t     r;
                        do { r = write(STDOUT_FILENO, msg, strlen(msg)); } while (r < 0 && errno == EINTR);
                    }
                    break;
                }
                continue;
            }
            auth_fails = 0;
            if (plen > 0) { /* len==0 is a cover-traffic dummy — silently discard */
                plain[plen] = '\0';
                sanitize_peer_text(plain, plen);
                cli_clear_input_line(line_len);
                secure_chat_print("peer", (char *)plain);
                cli_redraw_input(line, line_len);
            }
            crypto_wipe(plain, sizeof plain);
            crypto_wipe(frame, sizeof frame);
        }

        /* ----- Keyboard input (one byte at a time) -----
         *
         * In raw mode with VMIN=0/VTIME=0, read() returns 0 if no byte
         * is available.  We read one byte per iteration so each keystroke
         * is handled immediately. */
        if (g_running && (fds[1].revents & POLLIN)) {
            unsigned char ch = 0;
            ssize_t       rn = read(STDIN_FILENO, &ch, 1);
            if (rn <= 0) continue;

            /* Ctrl+C (0x03) or Ctrl+D (0x04): clean shutdown.
             * Since we cleared ISIG in termios, Ctrl+C arrives as a
             * literal byte rather than generating SIGINT. */
            if (ch == 0x03 || ch == 0x04) {
                g_running = 0;
                {
                    const char *msg = "\n";
                    ssize_t     r;
                    do { r = write(STDOUT_FILENO, msg, 1); } while (r < 0 && errno == EINTR);
                }
                break;
            }

            /* Backspace: delete last character.
             * 0x7F is the standard backspace on most modern terminals;
             * 0x08 (BS) is the legacy alternative. */
            if (ch == 0x7F || ch == 0x08) {
                if (line_len > 0) {
                    line[--line_len] = '\0';
                    /* Move cursor back, overwrite with space, move back again. */
                    const char *bs = "\b \b";
                    ssize_t     r;
                    do { r = write(STDOUT_FILENO, bs, 3); } while (r < 0 && errno == EINTR);
                }
                continue;
            }

            /* Enter: send the message if non-empty. */
            if (ch == '\r' || ch == '\n') {
                /* Print a newline to move past the current input line. */
                {
                    const char *nl = "\n";
                    ssize_t     r;
                    do { r = write(STDOUT_FILENO, nl, 1); } while (r < 0 && errno == EINTR);
                }

                if (line_len == 0) {
                    cli_redraw_input(line, line_len);
                    continue;
                }
                if (line_len > (size_t)MAX_MSG_RATCHET) {
                    const char *msg = "[too long]\n";
                    ssize_t     r;
                    do { r = write(STDOUT_FILENO, msg, strlen(msg)); } while (r < 0 && errno == EINTR);
                    crypto_wipe(line, sizeof line);
                    line_len = 0;
                    cli_redraw_input(line, line_len);
                    continue;
                }

                /* Build the encrypted frame.  Do not advance the chain
                 * until write_exact succeeds (same logic as the original). */
                if (frame_build(sess, (const uint8_t *)line, (uint16_t)line_len, frame, next_tx) != 0) {
                    crypto_wipe(line, sizeof line);
                    crypto_wipe(frame, sizeof frame);
                    crypto_wipe(next_tx, sizeof next_tx);
                    break;
                }

                if (write_exact(fd, frame, FRAME_SZ) != 0) {
                    const char *msg = "[send error]\n";
                    ssize_t     r;
                    do { r = write(STDOUT_FILENO, msg, strlen(msg)); } while (r < 0 && errno == EINTR);
                    crypto_wipe(line, sizeof line);
                    crypto_wipe(frame, sizeof frame);
                    crypto_wipe(next_tx, sizeof next_tx);
                    break;
                }

                /* Write succeeded -- commit the chain advance. */
                memcpy(sess->tx, next_tx, KEY);
                sess->tx_seq++;
                /* Cover timer NOT reset on real sends — schedule runs independently
                 * so real messages blend into the cover traffic pattern. */

                /* Print our own message, then redraw prompt for next input. */
                secure_chat_print(" me", line);

                crypto_wipe(line, sizeof line);
                crypto_wipe(frame, sizeof frame);
                crypto_wipe(next_tx, sizeof next_tx);
                line_len = 0;
                cli_redraw_input(line, line_len);
                continue;
            }

            /* Printable ASCII characters: append to the line buffer and
             * echo the character to the terminal. */
            if (ch >= 0x20 && ch <= 0x7E) {
                if (line_len < (size_t)MAX_MSG_RATCHET) {
                    line[line_len++] = (char)ch;
                    line[line_len]   = '\0';
                    ssize_t r;
                    do { r = write(STDOUT_FILENO, &ch, 1); } while (r < 0 && errno == EINTR);
                }
                continue;
            }

            /* Any other byte (escape sequences, UTF-8 continuations, etc.)
             * is silently ignored.  This keeps things simple and avoids
             * rendering issues with multi-byte sequences in the line buffer. */
        }

        /* ---- Cover traffic: send encrypted dummy frame on schedule ---- */
        if (cover && g_running && monotonic_ms() >= next_cover) {
            if (frame_build(sess, NULL, 0, frame, next_tx) != 0) break;
            if (write_exact(fd, frame, FRAME_SZ) != 0) break;
            memcpy(sess->tx, next_tx, KEY);
            sess->tx_seq++;
            crypto_wipe(frame, sizeof frame);
            crypto_wipe(next_tx, sizeof next_tx);
            next_cover = monotonic_ms() + (uint64_t)cover_delay_ms();
        }
    }

    /* Wipe all sensitive data from the stack before returning. */
    crypto_wipe(line, sizeof line);
    crypto_wipe(frame, sizeof frame);
    crypto_wipe(next_tx, sizeof next_tx);
    crypto_wipe(plain, sizeof plain);
}

/* ---- Cooked-mode fallback -----------------------------------------------
 *
 * When stdin is not a TTY (piped input, redirected file), we cannot use
 * raw termios.  Fall back to the original cooked-mode loop: the OS
 * handles line editing internally and delivers complete lines. */
static void cli_chat_loop_cooked(socket_t fd, session_t *sess, int cover) {
    uint8_t  frame[FRAME_SZ];
    uint8_t  next_tx[KEY];
    uint8_t  plain[MAX_MSG + 1];
    char     line[MAX_MSG + 2];
    uint16_t plen;
    int      auth_fails = 0;
    uint64_t next_cover = cover ? monotonic_ms() + (uint64_t)cover_delay_ms() : 0;

    memset(frame, 0, sizeof frame);
    memset(line, 0, sizeof line);

    while (g_running) {
        struct pollfd fds[2];
        int           ready;

        fds[0].fd     = fd;
        fds[0].events = POLLIN;
        fds[1].fd     = STDIN_FILENO;
        fds[1].events = POLLIN;

        int timeout = cover ? 250 : -1;
        if (cover) {
            int64_t remain = (int64_t)(next_cover - monotonic_ms());
            if (remain <= 0) timeout = 0;
            else if (remain < timeout) timeout = (int)remain;
        }

        ready = poll(fds, 2, timeout);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* ----- Incoming encrypted frame from peer ----- */
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            if (read_exact_dl(fd, frame, FRAME_SZ, monotonic_ms() + (uint64_t)FRAME_TIMEOUT_S * 1000) != 0) {
                printf("\n  [peer disconnected]\n");
                break;
            }
            plen      = 0;
            int fo_rc = frame_open(sess, frame, plain, &plen);
            if (fo_rc != 0) {
                crypto_wipe(frame, sizeof frame);
                crypto_wipe(plain, sizeof plain);
                if (fo_rc == -2 || ++auth_fails >= MAX_AUTH_FAILURES) {
                    fprintf(stderr, "[session error: authentication or sequence failure]\n");
                    break;
                }
                continue;
            }
            auth_fails = 0;
            if (plen > 0) { /* len==0 is a cover-traffic dummy — silently discard */
                plain[plen] = '\0';
                sanitize_peer_text(plain, plen);
                secure_chat_print("peer", (char *)plain);
            }
            crypto_wipe(plain, sizeof plain);
            crypto_wipe(frame, sizeof frame);
        }

        /* ----- Outgoing message typed by the user ----- */
        if (g_running && (fds[1].revents & POLLIN)) {
            /* read() instead of fgets() to bypass libc's stdin buffer.
             * fgets copies user input into an internal ~4KB buffer that is
             * never wiped; read() goes straight from kernel to our buffer.
             * In cooked (canonical) mode the terminal driver still handles
             * line editing (backspace, Ctrl+U, etc.) and delivers a complete
             * line when the user presses Enter. */
            ssize_t rn = read(STDIN_FILENO, line, sizeof line - 1);
            if (rn <= 0) break;
            size_t n = (size_t)rn;
            line[n]  = '\0';
            if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
            if (n == 0) {
                crypto_wipe(line, sizeof line);
                continue;
            }
            if (n > (size_t)MAX_MSG_RATCHET) {
                printf("[too long -- max %d bytes]\n", MAX_MSG_RATCHET);
                crypto_wipe(line, sizeof line);
                continue;
            }

            /* Build the frame (compute next_chain) but do not advance
             * the chain yet -- only commit after a successful write. */
            if (frame_build(sess, (const uint8_t *)line, (uint16_t)n, frame, next_tx) != 0) {
                crypto_wipe(line, sizeof line);
                crypto_wipe(frame, sizeof frame);
                crypto_wipe(next_tx, sizeof next_tx);
                break;
            }

            if (write_exact(fd, frame, FRAME_SZ) != 0) {
                fprintf(stderr, "[send error]\n");
                crypto_wipe(line, sizeof line);
                crypto_wipe(frame, sizeof frame);
                crypto_wipe(next_tx, sizeof next_tx);
                break;
            }

            /* Write succeeded -- now commit the chain advance. */
            memcpy(sess->tx, next_tx, KEY);
            sess->tx_seq++;
            /* Cover timer NOT reset on real sends — schedule runs independently
             * so real messages blend into the cover traffic pattern. */

            secure_chat_print(" me", line);

            crypto_wipe(line, sizeof line);
            crypto_wipe(frame, sizeof frame);
            crypto_wipe(next_tx, sizeof next_tx);
        }

        /* ---- Cover traffic: send encrypted dummy frame on schedule ---- */
        if (cover && g_running && monotonic_ms() >= next_cover) {
            if (frame_build(sess, NULL, 0, frame, next_tx) != 0) break;
            if (write_exact(fd, frame, FRAME_SZ) != 0) break;
            memcpy(sess->tx, next_tx, KEY);
            sess->tx_seq++;
            crypto_wipe(frame, sizeof frame);
            crypto_wipe(next_tx, sizeof next_tx);
            next_cover = monotonic_ms() + (uint64_t)cover_delay_ms();
        }
    }

    /* Wipe all sensitive data from the stack before returning. */
    crypto_wipe(line, sizeof line);
    crypto_wipe(frame, sizeof frame);
    crypto_wipe(next_tx, sizeof next_tx);
    crypto_wipe(plain, sizeof plain);
}

/* ---- Public entry point -------------------------------------------------
 *
 * Try to enter raw mode.  If stdin is a TTY and raw mode succeeds, use
 * the raw-mode loop with prompt and per-keystroke handling.  Otherwise,
 * fall back to the cooked-mode loop for piped/redirected input. */
void cli_chat_loop(socket_t fd, session_t *sess, int cover) {
    if (cli_init_raw_mode()) cli_chat_loop_raw(fd, sess, cover);
    else cli_chat_loop_cooked(fd, sess, cover);
}

#endif /* !_WIN32 */
