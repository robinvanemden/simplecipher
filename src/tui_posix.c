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
static struct termios tui_orig_termios;
static volatile int   tui_resize_flag = 0;

static void tui_sigwinch(int sig) {
    (void)sig;
    tui_resize_flag = 1;
}

/* Restore the terminal to its original cooked mode.
 * Also re-enables the cursor and resets text colours so the user's shell
 * is not left with invisible text or dim colours after exit. */
void tui_restore_term(void) {
    printf("\033[?25h"); /* show cursor */
    printf("\033[0 q");  /* restore default cursor shape */
    printf("\033[0m");   /* reset colors */
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

    printf("\033[?25l"); /* hide cursor while drawing the UI frame */
    printf("\033[2J");   /* clear screen */
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
    uint64_t    next_cover = cover ? monotonic_ms() + (uint64_t)cover_delay_ms() : 0;

    memset(line, 0, sizeof line);
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

        /* ----- Incoming frame from peer ----- */
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            /* Per-frame deadline: a real 512-byte frame completes in
             * milliseconds once poll() says data arrived.  The deadline
             * defeats byte-dribble attacks that reset SO_RCVTIMEO by
             * sending one byte just under the per-syscall timeout. */
            if (read_exact_dl(fd, frame, FRAME_SZ, monotonic_ms() + (uint64_t)FRAME_TIMEOUT_S * 1000) != 0) {
                tui_msg_add(TUI_SYSTEM, "[peer disconnected]");
                status = "Peer disconnected  |  Ctrl+C to exit";
                tui_draw_screen(status, line, line_len);
                break;
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

        /* ----- Keyboard input ----- */
        if (g_running && (fds[1].revents & POLLIN)) {
            unsigned char ch = 0;
            if (read(STDIN_FILENO, &ch, 1) != 1) continue;

            if (ch == 0x03 || ch == 0x04) {
                g_running = 0;
                break;
            }
            if (ch == 0x7F || ch == 0x08) {
                if (line_len > 0) {
                    line[--line_len] = '\0';
                    tui_draw_input(line, line_len);
                }
                continue;
            }
            if (ch == '\r' || ch == '\n') {
                if (line_len == 0) continue;
                if (line_len > (size_t)MAX_MSG_RATCHET) {
                    tui_msg_add(TUI_SYSTEM, "[message too long]");
                    tui_draw_messages();
                    tui_draw_input(line, line_len);
                    continue;
                }

                if (frame_build(sess, (const uint8_t *)line, (uint16_t)line_len, frame, next_tx) != 0) {
                    crypto_wipe(line, sizeof line);
                    crypto_wipe(frame, sizeof frame);
                    crypto_wipe(next_tx, sizeof next_tx);
                    break;
                }
                if (write_exact(fd, frame, FRAME_SZ) != 0) {
                    tui_msg_add(TUI_SYSTEM, "[send error]");
                    tui_draw_messages();
                    crypto_wipe(line, sizeof line);
                    crypto_wipe(frame, sizeof frame);
                    crypto_wipe(next_tx, sizeof next_tx);
                    break;
                }

                memcpy(sess->tx, next_tx, KEY);
                sess->tx_seq++;
                /* Cover timer NOT reset on real sends — schedule runs independently
                 * so real messages blend into the cover traffic pattern. */

                tui_msg_add(TUI_ME, line);
                crypto_wipe(line, sizeof line);
                line_len = 0;
                tui_draw_messages();
                tui_draw_input(line, line_len);

                crypto_wipe(frame, sizeof frame);
                crypto_wipe(next_tx, sizeof next_tx);
                continue;
            }
            if (ch >= 0x20 && ch <= 0x7E && line_len < (size_t)MAX_MSG_RATCHET) {
                line[line_len++] = (char)ch;
                line[line_len]   = '\0';
                tui_draw_input(line, line_len);
            }
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

    crypto_wipe(line, sizeof line);
    crypto_wipe(frame, sizeof frame);
    crypto_wipe(next_tx, sizeof next_tx);
    crypto_wipe(plain, sizeof plain);
    tui_msg_wipe();
}
