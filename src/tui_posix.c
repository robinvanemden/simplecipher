/*
 * tui_posix.c — POSIX TUI terminal setup and chat event loop
 *
 * This file is compiled only on POSIX systems (Linux, macOS, BSD).
 * It provides tui_init_term(), tui_restore_term(), and tui_chat_loop()
 * using termios for raw mode and poll() for the event loop.
 *
 * The Windows equivalents live in tui_win.c with the same function names;
 * only one file is compiled per platform.
 */

#include "tui.h"
#include <termios.h>
#include <sys/ioctl.h>

enum { RAW_INPUT_BUF = 256 }; /* batch keyboard read buffer size */

/* ---- TUI: terminal setup (POSIX) ----------------------------------------
 *
 * On POSIX systems, terminal behaviour is controlled by the termios
 * structure.  We save the original, switch to raw mode, and register
 * an atexit handler to restore it -- even on abnormal exits.
 *
 * SIGWINCH fires when the user resizes the terminal window.  We set a
 * flag and let the main loop redraw on its next iteration rather than
 * drawing from the signal handler (which is not safe -- printf is not
 * async-signal-safe). */
static struct termios        tui_orig_termios;
static volatile sig_atomic_t tui_resize_flag = 0;

static void tui_sigwinch(int sig) {
    (void)sig;
    tui_resize_flag = 1;
}

/* Emergency handler for SIGTERM / SIGSEGV / SIGABRT: restore the terminal
 * so the user's shell is not left in raw mode with a hidden cursor.
 * Only async-signal-safe functions (write, tcsetattr, _exit) are used. */
static void tui_emergency_restore(int sig) {
    (void)sig;
    /* Best-effort terminal restore — these are all async-signal-safe. */
    static const char reset_seq[] = "\033[?25h\033[0 q\033[0m\033[?1049l";
    ssize_t           wr;
    wr = write(STDOUT_FILENO, reset_seq, sizeof reset_seq - 1);
    (void)wr; /* best-effort; nothing useful to do on failure */
    tcsetattr(STDIN_FILENO, TCSANOW, &tui_orig_termios);
    _exit(128 + sig);
}

/* Restore the terminal to its original cooked mode.
 * Also re-enables the cursor and resets text colours so the user's shell
 * is not left with invisible text or dim colours after exit. */
void tui_restore_term(void) {
    printf("\033[?25h");   /* show cursor */
    printf("\033[0 q");    /* restore default cursor shape */
    printf("\033[0m");     /* reset colors */
    printf("\033[?1049l"); /* leave alternate screen buffer — erases all
                           * chat content and restores the original screen */
    fflush(stdout);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tui_orig_termios);
}

/* Switch terminal to raw mode for full keystroke control.
 *
 * Flags cleared:
 *   ECHO    -- don't echo typed characters (we draw our own input line)
 *   ICANON  -- don't buffer until Enter (deliver each byte immediately)
 *   ISIG    -- don't generate SIGINT on Ctrl+C (we handle it as a keypress)
 *   IXON    -- don't intercept Ctrl+S/Ctrl+Q for flow control
 *   ICRNL   -- don't translate \r to \n (we check for both explicitly)
 *
 * VMIN=0, VTIME=0: non-blocking reads -- read() returns immediately with
 * 0 bytes if nothing is available, so we never block inside the poll loop. */
void tui_init_term(void) {
    struct termios   raw;
    struct sigaction sa = {0};

    tcgetattr(STDIN_FILENO, &tui_orig_termios);
    atexit(tui_restore_term);

    raw = tui_orig_termios;
    raw.c_lflag &= (tcflag_t) ~(ECHO | ICANON | ISIG);
    raw.c_iflag &= (tcflag_t) ~(IXON | ICRNL);
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

    sa.sa_handler = tui_sigwinch;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGWINCH, &sa, nullptr);

    /* Restore the terminal on fatal signals so the user's shell is usable.
     * SA_RESETHAND prevents infinite loops (e.g. SIGSEGV inside handler). */
    sa.sa_handler = tui_emergency_restore;
    sa.sa_flags   = (int)SA_RESETHAND;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);

    printf("\033[?1049h"); /* enter alternate screen buffer — chat never
                           * touches the user's previous scrollback, and
                           * leaving the alternate buffer on exit erases
                           * all chat content from the terminal. */
    printf("\033[?25l");   /* hide cursor while drawing the UI frame */
    printf("\033[2J");     /* clear screen */
    fflush(stdout);
}

/* ---- TUI: POSIX chat event loop -----------------------------------------
 *
 * Same single-threaded poll() design as the CLI loop, but instead
 * of line-buffered stdin (fgets), we read raw bytes one at a time from
 * the terminal in raw mode and redraw the TUI after each event.
 *
 * Key differences from the CLI loop:
 *   - Keyboard input is raw bytes, not newline-terminated lines.
 *     Backspace (0x7F/0x08) deletes the last character.
 *     Ctrl+C (0x03) / Ctrl+D (0x04) set g_running=0 for clean exit.
 *   - poll() uses a 250ms timeout so we can check tui_resize_flag
 *     periodically (SIGWINCH sets the flag but doesn't redraw directly).
 *   - Every incoming message triggers a message-area redraw to keep
 *     the ring buffer display in sync. */
void tui_chat_loop(socket_t fd, session_t *sess, int cover) {
    char        line[MAX_MSG + 1];
    size_t      line_len = 0;
    uint8_t     frame[FRAME_SZ];
    uint8_t     next_tx[KEY];
    uint8_t     plain[MAX_MSG + 1];
    uint16_t    plen;
    const char *status     = "Secure session active  |  Ctrl+C to quit";
    int         auth_fails = 0;
    int         rx_count   = 0;
    uint64_t    rx_window  = 0;
    uint64_t    next_cover = cover ? monotonic_ms() + (uint64_t)cover_delay_ms() : 0;
    uint8_t     pending_msg[MAX_MSG + 1]; /* queued real message for cover tick */
    uint16_t    pending_len = 0;

    memset(line, 0, sizeof line);
    memset(pending_msg, 0, sizeof pending_msg);
    tui_draw_screen(status, line, line_len);

    while (g_running) {
        struct pollfd fds[2];
        int           ready;

        if (tui_resize_flag) {
            tui_resize_flag = 0;
            tui_draw_screen(status, line, line_len);
        }

        fds[0].fd     = fd;
        fds[0].events = POLLIN;
        fds[1].fd     = STDIN_FILENO;
        fds[1].events = POLLIN;

        int timeout = POLL_INTERVAL_MS;
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

        /* ----- Incoming frame from peer ----- */
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            /* Per-frame deadline: a real 512-byte frame completes in
             * milliseconds once poll() says data arrived.  The deadline
             * defeats byte-dribble attacks that reset SO_RCVTIMEO by
             * sending one byte just under the per-syscall timeout. */
            if (frame_recv(fd, frame, monotonic_ms() + (uint64_t)FRAME_TIMEOUT_S * 1000) != 0) {
                tui_msg_add(TUI_SYSTEM, "[peer disconnected]");
                status = "Peer disconnected  |  Ctrl+C to exit";
                tui_draw_screen(status, line, line_len);
                break;
            }
            {
                uint64_t now_rl = monotonic_ms();
                if (now_rl - rx_window >= 1000) { rx_count = 1; rx_window = now_rl; }
                else if (++rx_count > 50) { crypto_wipe(frame, sizeof frame); continue; }
            }
            plen      = 0;
            int fo_rc = frame_open(sess, frame, plain, &plen);
            if (fo_rc != 0) {
                crypto_wipe(frame, sizeof frame);
                crypto_wipe(plain, sizeof plain);
                if (fo_rc == -2 || ++auth_fails >= MAX_AUTH_FAILURES) {
                    tui_msg_add(TUI_SYSTEM, "[session error]");
                    status = "Session error  |  Ctrl+C to exit";
                    tui_draw_screen(status, line, line_len);
                    break;
                }
                continue;
            }
            auth_fails = 0;
            if (plen > 0) { /* len==0 is a cover-traffic dummy — silently discard */
                plain[plen] = '\0';
                sanitize_peer_text(plain, plen);
                tui_msg_add(TUI_PEER, (char *)plain);
                tui_draw_messages();
                tui_draw_input(line, line_len);
            }
            crypto_wipe(plain, sizeof plain);
            crypto_wipe(frame, sizeof frame);
        }

        /* ----- Keyboard input (batch: read multiple bytes for paste) ----- */
        if (g_running && (fds[1].revents & POLLIN)) {
            unsigned char inbuf[RAW_INPUT_BUF];
            ssize_t       sr = read(STDIN_FILENO, inbuf, sizeof inbuf);
            if (sr <= 0) continue;

            for (ssize_t bi = 0; bi < sr; bi++) {
                unsigned char ch = inbuf[bi];

                if (ch == 0x03 || ch == 0x04) {
                    g_running = 0;
                    break;
                }
                if (ch == 0x7F || ch == 0x08) {
                    if (line_len > 0) line[--line_len] = '\0';
                    continue;
                }
                if (ch == '\r' || ch == '\n') {
                    if (line_len == 0) continue;
                    if (line_len > (size_t)MAX_MSG_RATCHET) {
                        tui_msg_add(TUI_SYSTEM, "[message too long]");
                        tui_draw_messages();
                        continue;
                    }

                    if (cover) {
                        /* Queue for next cover tick — all outgoing frames
                         * follow the same timing distribution. */
                        if (pending_len > 0) continue;
                        memcpy(pending_msg, line, line_len);
                        pending_len = (uint16_t)line_len;
                        tui_msg_add(TUI_ME_QUEUED, line);
                        crypto_wipe(line, sizeof line);
                        line_len = 0;
                        tui_draw_messages();
                        continue;
                    }

                    if (frame_build(sess, (const uint8_t *)line, (uint16_t)line_len, frame, next_tx) != 0) {
                        crypto_wipe(line, sizeof line);
                        crypto_wipe(frame, sizeof frame);
                        crypto_wipe(next_tx, sizeof next_tx);
                        break;
                    }
                    if (frame_send(fd, frame, monotonic_ms() + (uint64_t)FRAME_TIMEOUT_S * 1000) != 0) {
                        tui_msg_add(TUI_SYSTEM, "[send error]");
                        tui_draw_messages();
                        crypto_wipe(line, sizeof line);
                        crypto_wipe(frame, sizeof frame);
                        crypto_wipe(next_tx, sizeof next_tx);
                        break;
                    }

                    memcpy(sess->tx, next_tx, KEY);
                    sess->tx_seq++;

                    tui_msg_add(TUI_ME, line);
                    crypto_wipe(line, sizeof line);
                    line_len = 0;
                    tui_draw_messages();

                    crypto_wipe(frame, sizeof frame);
                    crypto_wipe(next_tx, sizeof next_tx);
                    continue;
                }
                if (ch >= 0x20 && ch <= 0x7E && line_len < (size_t)MAX_MSG_RATCHET) {
                    line[line_len++] = (char)ch;
                    line[line_len]   = '\0';
                }
            }
            crypto_wipe(inbuf, sizeof inbuf); /* wipe raw keystrokes */
            /* Single redraw after processing all buffered bytes */
            tui_draw_input(line, line_len);
        }

        /* ---- Cover traffic: single send point for all outgoing frames.
         * Queued real messages replace the cover payload so every frame
         * follows the same timing distribution — defeating analysis. */
        if (cover && g_running && monotonic_ms() >= next_cover) {
            const uint8_t *payload = pending_len > 0 ? pending_msg : NULL;
            uint16_t       tx_len  = pending_len;
            if (frame_build(sess, payload, tx_len, frame, next_tx) != 0) {
                tui_msg_add(TUI_SYSTEM, "cover traffic error -- session ended");
                tui_draw_screen(status, line, line_len);
                break;
            }
            if (frame_send(fd, frame, monotonic_ms() + (uint64_t)FRAME_TIMEOUT_S * 1000) != 0) {
                tui_msg_add(TUI_SYSTEM, "cover traffic error -- session ended");
                tui_draw_screen(status, line, line_len);
                break;
            }
            memcpy(sess->tx, next_tx, KEY);
            sess->tx_seq++;
            if (pending_len > 0) {
                crypto_wipe(pending_msg, sizeof pending_msg);
                pending_len = 0;
            }
            crypto_wipe(frame, sizeof frame);
            crypto_wipe(next_tx, sizeof next_tx);
            next_cover = monotonic_ms() + (uint64_t)cover_delay_ms();
        }
    }

    if (pending_len > 0)
        fprintf(stderr, "[queued message was not sent]\n");
    crypto_wipe(line, sizeof line);
    crypto_wipe(frame, sizeof frame);
    crypto_wipe(next_tx, sizeof next_tx);
    crypto_wipe(plain, sizeof plain);
    crypto_wipe(pending_msg, sizeof pending_msg);
    tui_msg_wipe();
}
