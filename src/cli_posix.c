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
    crypto_wipe(buf, sizeof buf);
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
    uint8_t  plain[MAX_MSG + 1];
    uint16_t plen;
    int      auth_fails = 0;
    int      rx_count   = 0;       /* inbound frame rate limiter */
    uint64_t rx_window  = 0;
    uint64_t next_cover = cover ? monotonic_ms() + (uint64_t)cover_delay_ms() : 0;
    uint8_t  pending_msg[MAX_MSG + 1];
    uint16_t pending_len = 0;
    nb_io_t  io;

    memset(line, 0, sizeof line);
    memset(pending_msg, 0, sizeof pending_msg);
    nb_io_init(&io);

    /* Show initial prompt. */
    cli_redraw_input(line, line_len);

    while (g_running) {
        struct pollfd fds[2];
        int           ready;

        fds[0].fd     = fd;
        fds[0].events = POLLIN | (io.out_active ? POLLOUT : 0);
        fds[1].fd     = STDIN_FILENO;
        fds[1].events = POLLIN;

        int timeout = POLL_INTERVAL_MS;
        if (cover) {
            int64_t remain = (int64_t)(next_cover - monotonic_ms());
            if (remain <= 0) timeout = 0;
            else if (remain < timeout) timeout = (int)remain;
        }
        if (io.out_active) {
            /* Keep polling short while send is in flight. */
            if (timeout > 50) timeout = 50;
        }

        ready = poll(fds, 2, timeout);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* ----- Stale partial frame check ----- */
        if (io.in_have > 0 &&
            (monotonic_ms() - io.in_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) {
            cli_clear_input_line(line_len);
            {
                const char *msg = "[peer stalled mid-frame: disconnecting]\n";
                ssize_t     r;
                do { r = write(STDOUT_FILENO, msg, strlen(msg)); } while (r < 0 && errno == EINTR);
            }
            break;
        }
        if (io.out_active &&
            (monotonic_ms() - io.out_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) {
            cli_clear_input_line(line_len);
            {
                const char *msg = "[send timeout]\n";
                ssize_t     r;
                do { r = write(STDOUT_FILENO, msg, strlen(msg)); } while (r < 0 && errno == EINTR);
            }
            break;
        }

        /* ----- Incoming bytes from peer (non-blocking accumulation) -----
         *
         * Read available bytes into in_wire.  When a full padded frame
         * is assembled, decrypt and display it.  This never blocks —
         * Ctrl+C stays responsive even if the peer dribbles bytes. */
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            int r = nb_try_recv(fd, io.in_wire + io.in_have,
                                io.in_need - io.in_have);
            if (r < 0) {
                cli_clear_input_line(line_len);
                {
                    const char *msg = "\n  [peer disconnected]\n";
                    ssize_t     wr;
                    do { wr = write(STDOUT_FILENO, msg, strlen(msg)); } while (wr < 0 && errno == EINTR);
                }
                break;
            }
            if (r > 0) {
                if (io.in_have == 0) io.in_start_ms = monotonic_ms();
                io.in_have += (size_t)r;

                /* Phase 1 complete: pad_len byte received. */
                if (io.in_have >= io.in_need && io.in_need == WIRE_HDR) {
                    io.in_need = WIRE_HDR + FRAME_SZ + (size_t)io.in_wire[0];
                }

                /* Phase 2 complete: full padded frame assembled. */
                if (io.in_have >= io.in_need && io.in_need > WIRE_HDR) {
                    /* Rate-limit before expensive AEAD + X25519 work. */
                    uint64_t now_rl = monotonic_ms();
                    if (now_rl - rx_window >= 1000) { rx_count = 1; rx_window = now_rl; }
                    else if (++rx_count > 50) {
                        /* Drop silently — peer is flooding. */
                        crypto_wipe(io.in_wire, sizeof io.in_wire);
                        io.in_have = 0; io.in_need = WIRE_HDR; io.in_start_ms = 0;
                        goto after_recv;
                    }

                    plen = 0;
                    int fo_rc = frame_open(sess, io.in_wire + WIRE_HDR, plain, &plen);
                    crypto_wipe(io.in_wire, sizeof io.in_wire);
                    io.in_have = 0; io.in_need = WIRE_HDR; io.in_start_ms = 0;

                    if (fo_rc != 0) {
                        crypto_wipe(plain, sizeof plain);
                        if (fo_rc == -2 || ++auth_fails >= MAX_AUTH_FAILURES) {
                            cli_clear_input_line(line_len);
                            {
                                const char *msg = "[session error: authentication or sequence failure]\n";
                                ssize_t     wr;
                                do { wr = write(STDOUT_FILENO, msg, strlen(msg)); } while (wr < 0 && errno == EINTR);
                            }
                            break;
                        }
                        goto after_recv;
                    }
                    auth_fails = 0;
                    if (plen > 0) {
                        plain[plen] = '\0';
                        sanitize_peer_text(plain, plen);
                        cli_clear_input_line(line_len);
                        secure_chat_print("peer", (char *)plain);
                        cli_redraw_input(line, line_len);
                    }
                    crypto_wipe(plain, sizeof plain);
                }
            }
        }
after_recv:

        /* ----- Outbound send completion (non-blocking drain) ----- */
        if (io.out_active && (fds[0].revents & POLLOUT)) {
            int s = nb_try_send(fd, io.out_wire + io.out_off,
                                io.out_len - io.out_off);
            if (s < 0) {
                cli_clear_input_line(line_len);
                {
                    const char *msg = "[send error]\n";
                    ssize_t     r;
                    do { r = write(STDOUT_FILENO, msg, strlen(msg)); } while (r < 0 && errno == EINTR);
                }
                break;
            }
            if (s > 0) io.out_off += (size_t)s;
            if (io.out_off == io.out_len) {
                /* Send complete — commit chain state. */
                memcpy(sess->tx, io.out_next_tx, KEY);
                sess->tx_seq++;
                io.out_active = 0;
                if (pending_len > 0) {
                    crypto_wipe(pending_msg, sizeof pending_msg);
                    pending_len = 0;
                }
                if (io.out_text[0]) {
                    secure_chat_print(" me", io.out_text);
                    cli_redraw_input(line, line_len);
                }
                crypto_wipe(io.out_wire, sizeof io.out_wire);
                crypto_wipe(io.out_next_tx, sizeof io.out_next_tx);
                crypto_wipe(io.out_text, sizeof io.out_text);
                if (cover)
                    next_cover = monotonic_ms() + (uint64_t)cover_delay_ms();
            }
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

            if (ch == 0x03 || ch == 0x04) {
                g_running = 0;
                {
                    const char *msg = "\n";
                    ssize_t     r;
                    do { r = write(STDOUT_FILENO, msg, 1); } while (r < 0 && errno == EINTR);
                }
                break;
            }

            if (ch == 0x7F || ch == 0x08) {
                if (line_len > 0) {
                    line[--line_len] = '\0';
                    const char *bs = "\b \b";
                    ssize_t     r;
                    do { r = write(STDOUT_FILENO, bs, 3); } while (r < 0 && errno == EINTR);
                }
                continue;
            }

            /* Enter: send the message if non-empty. */
            if (ch == '\r' || ch == '\n') {
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

                if (cover) {
                    if (pending_len > 0) {
                        cli_redraw_input(line, line_len);
                        continue;
                    }
                    memcpy(pending_msg, line, line_len);
                    pending_len = (uint16_t)line_len;
                    secure_chat_print(" me (queued)", line);
                    crypto_wipe(line, sizeof line);
                    line_len = 0;
                    cli_redraw_input(line, line_len);
                    continue;
                }

                /* Non-cover immediate send (non-blocking). */
                if (io.out_active) {
                    const char *msg = "[send still in progress]\n";
                    ssize_t     r;
                    do { r = write(STDOUT_FILENO, msg, strlen(msg)); } while (r < 0 && errno == EINTR);
                    cli_redraw_input(line, line_len);
                    continue;
                }

                {
                    uint8_t out_frame[FRAME_SZ];
                    if (frame_build(sess, (const uint8_t *)line, (uint16_t)line_len,
                                    out_frame, io.out_next_tx) != 0) {
                        crypto_wipe(out_frame, sizeof out_frame);
                        break;
                    }
                    io.out_len = frame_wire_build(io.out_wire, out_frame);
                    crypto_wipe(out_frame, sizeof out_frame);
                }
                memcpy(io.out_text, line, line_len);
                io.out_text[line_len] = '\0';
                crypto_wipe(line, sizeof line);
                line_len       = 0;
                io.out_off     = 0;
                io.out_active  = 1;
                io.out_start_ms = monotonic_ms();

                /* Try to send immediately. */
                int s = nb_try_send(fd, io.out_wire, io.out_len);
                if (s < 0) {
                    const char *msg = "[send error]\n";
                    ssize_t     r;
                    do { r = write(STDOUT_FILENO, msg, strlen(msg)); } while (r < 0 && errno == EINTR);
                    break;
                }
                if (s > 0) io.out_off += (size_t)s;
                if (io.out_off == io.out_len) {
                    memcpy(sess->tx, io.out_next_tx, KEY);
                    sess->tx_seq++;
                    io.out_active = 0;
                    secure_chat_print(" me", io.out_text);
                    crypto_wipe(io.out_wire, sizeof io.out_wire);
                    crypto_wipe(io.out_next_tx, sizeof io.out_next_tx);
                    crypto_wipe(io.out_text, sizeof io.out_text);
                }
                cli_redraw_input(line, line_len);
                continue;
            }

            if (ch >= 0x20 && ch <= 0x7E) {
                if (line_len < (size_t)MAX_MSG_RATCHET) {
                    line[line_len++] = (char)ch;
                    line[line_len]   = '\0';
                    ssize_t r;
                    do { r = write(STDOUT_FILENO, &ch, 1); } while (r < 0 && errno == EINTR);
                }
                continue;
            }
        }

        /* ---- Cover traffic: single send point for all outgoing frames.
         * Queued real messages replace the cover payload so every frame
         * follows the same timing distribution — defeating analysis.
         * Skipped if an async send is already in flight. */
        if (cover && g_running && !io.out_active && monotonic_ms() >= next_cover) {
            const uint8_t *payload = pending_len > 0 ? pending_msg : NULL;
            uint16_t       tx_len  = pending_len;
            uint8_t        out_frame[FRAME_SZ];
            if (frame_build(sess, payload, tx_len, out_frame, io.out_next_tx) != 0) {
                crypto_wipe(out_frame, sizeof out_frame);
                secure_chat_print("system", "cover traffic error -- session ended");
                break;
            }
            io.out_len = frame_wire_build(io.out_wire, out_frame);
            crypto_wipe(out_frame, sizeof out_frame);
            io.out_off      = 0;
            io.out_active   = 1;
            io.out_start_ms = monotonic_ms();
            io.out_text[0]  = '\0'; /* cover frame: no display on completion */

            int s = nb_try_send(fd, io.out_wire, io.out_len);
            if (s < 0) {
                secure_chat_print("system", "cover traffic error -- session ended");
                break;
            }
            if (s > 0) io.out_off += (size_t)s;
            if (io.out_off == io.out_len) {
                memcpy(sess->tx, io.out_next_tx, KEY);
                sess->tx_seq++;
                io.out_active = 0;
                if (pending_len > 0) {
                    crypto_wipe(pending_msg, sizeof pending_msg);
                    pending_len = 0;
                }
                crypto_wipe(io.out_wire, sizeof io.out_wire);
                crypto_wipe(io.out_next_tx, sizeof io.out_next_tx);
                next_cover = monotonic_ms() + (uint64_t)cover_delay_ms();
            }
        }
    }

    if (pending_len > 0 || (io.out_active && io.out_text[0])) {
        const char *msg = "  [message was not sent]\n";
        ssize_t     r;
        do { r = write(STDOUT_FILENO, msg, strlen(msg)); } while (r < 0 && errno == EINTR);
    }
    crypto_wipe(line, sizeof line);
    crypto_wipe(plain, sizeof plain);
    crypto_wipe(pending_msg, sizeof pending_msg);
    nb_io_wipe(&io);
}

/* ---- Cooked-mode fallback -----------------------------------------------
 *
 * When stdin is not a TTY (piped input, redirected file), we cannot use
 * raw termios.  Fall back to the original cooked-mode loop: the OS
 * handles line editing internally and delivers complete lines. */
static void cli_chat_loop_cooked(socket_t fd, session_t *sess, int cover) {
    uint8_t  plain[MAX_MSG + 1];
    char     line[MAX_MSG + 2];
    uint16_t plen;
    int      auth_fails = 0;
    int      rx_count   = 0;
    uint64_t rx_window  = 0;
    uint64_t next_cover = cover ? monotonic_ms() + (uint64_t)cover_delay_ms() : 0;
    uint8_t  pending_msg[MAX_MSG + 1];
    uint16_t pending_len = 0;
    nb_io_t  io;
    /* Staging buffer for piped/redirected input: read() may return
     * multiple newline-delimited lines in one call. */
    char     rdbuf[MAX_MSG + 2];
    size_t   rdbuf_len = 0;

    memset(line, 0, sizeof line);
    memset(pending_msg, 0, sizeof pending_msg);
    memset(rdbuf, 0, sizeof rdbuf);
    nb_io_init(&io);

    while (g_running) {
        struct pollfd fds[2];
        int           ready;

        fds[0].fd     = fd;
        fds[0].events = POLLIN | (io.out_active ? POLLOUT : 0);
        fds[1].fd     = STDIN_FILENO;
        fds[1].events = POLLIN;

        int timeout = cover ? POLL_INTERVAL_MS : (io.out_active ? 50 : -1);
        if (cover) {
            int64_t remain = (int64_t)(next_cover - monotonic_ms());
            if (remain <= 0) timeout = 0;
            else if (remain < timeout) timeout = (int)remain;
        }
        if (io.out_active && timeout > 50) timeout = 50;

        ready = poll(fds, 2, timeout);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Deadline checks for stalled partial I/O. */
        if (io.in_have > 0 &&
            (monotonic_ms() - io.in_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) {
            fprintf(stderr, "[peer stalled mid-frame: disconnecting]\n");
            break;
        }
        if (io.out_active &&
            (monotonic_ms() - io.out_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) {
            fprintf(stderr, "[send timeout]\n");
            break;
        }

        /* ----- Incoming bytes from peer (non-blocking) ----- */
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            int r = nb_try_recv(fd, io.in_wire + io.in_have,
                                io.in_need - io.in_have);
            if (r < 0) { printf("\n  [peer disconnected]\n"); break; }
            if (r > 0) {
                if (io.in_have == 0) io.in_start_ms = monotonic_ms();
                io.in_have += (size_t)r;
                if (io.in_have >= io.in_need && io.in_need == WIRE_HDR)
                    io.in_need = WIRE_HDR + FRAME_SZ + (size_t)io.in_wire[0];
                if (io.in_have >= io.in_need && io.in_need > WIRE_HDR) {
                    uint64_t now_rl = monotonic_ms();
                    if (now_rl - rx_window >= 1000) { rx_count = 1; rx_window = now_rl; }
                    else if (++rx_count > 50) {
                        crypto_wipe(io.in_wire, sizeof io.in_wire);
                        io.in_have = 0; io.in_need = WIRE_HDR; io.in_start_ms = 0;
                        goto cooked_after_recv;
                    }
                    plen = 0;
                    int fo_rc = frame_open(sess, io.in_wire + WIRE_HDR, plain, &plen);
                    crypto_wipe(io.in_wire, sizeof io.in_wire);
                    io.in_have = 0; io.in_need = WIRE_HDR; io.in_start_ms = 0;
                    if (fo_rc != 0) {
                        crypto_wipe(plain, sizeof plain);
                        if (fo_rc == -2 || ++auth_fails >= MAX_AUTH_FAILURES) {
                            fprintf(stderr, "[session error: authentication or sequence failure]\n");
                            break;
                        }
                        goto cooked_after_recv;
                    }
                    auth_fails = 0;
                    if (plen > 0) {
                        plain[plen] = '\0';
                        sanitize_peer_text(plain, plen);
                        secure_chat_print("peer", (char *)plain);
                    }
                    crypto_wipe(plain, sizeof plain);
                }
            }
        }
cooked_after_recv:

        /* ----- Outbound send completion ----- */
        if (io.out_active && (fds[0].revents & POLLOUT)) {
            int s = nb_try_send(fd, io.out_wire + io.out_off,
                                io.out_len - io.out_off);
            if (s < 0) { fprintf(stderr, "[send error]\n"); break; }
            if (s > 0) io.out_off += (size_t)s;
            if (io.out_off == io.out_len) {
                memcpy(sess->tx, io.out_next_tx, KEY);
                sess->tx_seq++;
                io.out_active = 0;
                if (pending_len > 0) {
                    crypto_wipe(pending_msg, sizeof pending_msg);
                    pending_len = 0;
                }
                if (io.out_text[0])
                    secure_chat_print(" me", io.out_text);
                crypto_wipe(io.out_wire, sizeof io.out_wire);
                crypto_wipe(io.out_next_tx, sizeof io.out_next_tx);
                crypto_wipe(io.out_text, sizeof io.out_text);
                if (cover)
                    next_cover = monotonic_ms() + (uint64_t)cover_delay_ms();
            }
        }

        /* ----- Outgoing message from piped/redirected stdin ----- */
        if (g_running && (fds[1].revents & POLLIN)) {
            size_t space = sizeof rdbuf - 1 - rdbuf_len;
            if (space == 0) {
                fprintf(stderr, "[line too long -- discarded]\n");
                crypto_wipe(rdbuf, sizeof rdbuf);
                rdbuf_len = 0;
                continue;
            }
            ssize_t rn = read(STDIN_FILENO, rdbuf + rdbuf_len, space);
            if (rn <= 0) break;
            rdbuf_len += (size_t)rn;
            rdbuf[rdbuf_len] = '\0';

            char *start = rdbuf;
            for (;;) {
                char *nl = memchr(start, '\n', rdbuf_len - (size_t)(start - rdbuf));
                if (!nl) break;
                size_t n = (size_t)(nl - start);
                if (n > 0 && start[n - 1] == '\r') n--;
                if (n == 0) { start = nl + 1; continue; }
                if (n > (size_t)MAX_MSG_RATCHET) {
                    printf("[too long -- max %d bytes]\n", MAX_MSG_RATCHET);
                    start = nl + 1;
                    continue;
                }
                memcpy(line, start, n);
                line[n] = '\0';
                start = nl + 1;

                if (cover) {
                    if (pending_len > 0) {
                        fprintf(stderr, "[message dropped: previous message still queued]\n");
                        crypto_wipe(line, sizeof line);
                        continue;
                    }
                    memcpy(pending_msg, line, n);
                    pending_len = (uint16_t)n;
                    secure_chat_print(" me (queued)", line);
                    crypto_wipe(line, sizeof line);
                    continue;
                }

                /* Non-cover: one send at a time.  Remaining lines
                 * stay in rdbuf for the next poll iteration. */
                if (io.out_active) break;

                {
                    uint8_t out_frame[FRAME_SZ];
                    if (frame_build(sess, (const uint8_t *)line, (uint16_t)n,
                                    out_frame, io.out_next_tx) != 0) {
                        crypto_wipe(out_frame, sizeof out_frame);
                        crypto_wipe(line, sizeof line);
                        goto cooked_done;
                    }
                    io.out_len = frame_wire_build(io.out_wire, out_frame);
                    crypto_wipe(out_frame, sizeof out_frame);
                }
                memcpy(io.out_text, line, n);
                io.out_text[n] = '\0';
                crypto_wipe(line, sizeof line);
                io.out_off      = 0;
                io.out_active   = 1;
                io.out_start_ms = monotonic_ms();

                int s = nb_try_send(fd, io.out_wire, io.out_len);
                if (s < 0) { fprintf(stderr, "[send error]\n"); goto cooked_done; }
                if (s > 0) io.out_off += (size_t)s;
                if (io.out_off == io.out_len) {
                    memcpy(sess->tx, io.out_next_tx, KEY);
                    sess->tx_seq++;
                    io.out_active = 0;
                    secure_chat_print(" me", io.out_text);
                    crypto_wipe(io.out_wire, sizeof io.out_wire);
                    crypto_wipe(io.out_next_tx, sizeof io.out_next_tx);
                    crypto_wipe(io.out_text, sizeof io.out_text);
                }
                break; /* one send per iteration */
            }
            size_t remaining = rdbuf_len - (size_t)(start - rdbuf);
            if (remaining > 0 && start != rdbuf)
                memmove(rdbuf, start, remaining);
            rdbuf_len = remaining;
            crypto_wipe(rdbuf + rdbuf_len, sizeof rdbuf - rdbuf_len);
        }

        /* ---- Cover traffic ---- */
        if (cover && g_running && !io.out_active && monotonic_ms() >= next_cover) {
            const uint8_t *payload = pending_len > 0 ? pending_msg : NULL;
            uint16_t       tx_len  = pending_len;
            uint8_t        out_frame[FRAME_SZ];
            if (frame_build(sess, payload, tx_len, out_frame, io.out_next_tx) != 0) {
                crypto_wipe(out_frame, sizeof out_frame);
                secure_chat_print("system", "cover traffic error -- session ended");
                break;
            }
            io.out_len = frame_wire_build(io.out_wire, out_frame);
            crypto_wipe(out_frame, sizeof out_frame);
            io.out_off      = 0;
            io.out_active   = 1;
            io.out_start_ms = monotonic_ms();
            io.out_text[0]  = '\0';

            int s = nb_try_send(fd, io.out_wire, io.out_len);
            if (s < 0) {
                secure_chat_print("system", "cover traffic error -- session ended");
                break;
            }
            if (s > 0) io.out_off += (size_t)s;
            if (io.out_off == io.out_len) {
                memcpy(sess->tx, io.out_next_tx, KEY);
                sess->tx_seq++;
                io.out_active = 0;
                if (pending_len > 0) {
                    crypto_wipe(pending_msg, sizeof pending_msg);
                    pending_len = 0;
                }
                crypto_wipe(io.out_wire, sizeof io.out_wire);
                crypto_wipe(io.out_next_tx, sizeof io.out_next_tx);
                next_cover = monotonic_ms() + (uint64_t)cover_delay_ms();
            }
        }
    }

cooked_done:
    if (pending_len > 0 || (io.out_active && io.out_text[0]))
        fprintf(stderr, "  [message was not sent]\n");
    crypto_wipe(rdbuf, sizeof rdbuf);
    crypto_wipe(line, sizeof line);
    crypto_wipe(plain, sizeof plain);
    crypto_wipe(pending_msg, sizeof pending_msg);
    nb_io_wipe(&io);
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
