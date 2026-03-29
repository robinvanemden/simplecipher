/*
 * tui_win.c — Windows TUI terminal setup and chat event loop
 *
 * This file is compiled only on Windows.  It provides tui_init_term(),
 * tui_restore_term(), and tui_chat_loop() using the Windows Console API.
 *
 * The POSIX equivalents live in tui_posix.c with the same function names;
 * only one file is compiled per platform.
 */

#include "tui.h"
#include "cli.h" /* for win_try_send() */

enum { CONSOLE_INPUT_RECORDS = 32 }; /* batch size for ReadConsoleInputA */

/* ---- TUI: terminal setup (Windows) --------------------------------------
 *
 * Windows consoles do not use termios.  Instead, we:
 *   1. Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING on the output handle so
 *      our ANSI escape sequences are interpreted instead of printed literally.
 *   2. Switch the output code page to UTF-8 (CP_UTF8 = 65001) so the
 *      box-drawing characters render correctly.
 *   3. Save and restore both settings via atexit.
 *
 * Raw keyboard input on Windows is handled separately in the event loop
 * using ReadConsoleInputA() + KEY_EVENT records rather than termios. */

#if defined(_WIN32) || defined(_WIN64)

static HANDLE tui_h_out         = INVALID_HANDLE_VALUE;
static DWORD  tui_orig_out_mode = 0;
static UINT   tui_orig_out_cp   = 0;

void tui_restore_term(void) {
    printf("\033[?25h");
    printf("\033[0 q"); /* restore default cursor shape */
    printf("\033[0m");
    printf("\033[?1049l"); /* leave alternate screen buffer */
    fflush(stdout);
    if (tui_h_out != INVALID_HANDLE_VALUE) SetConsoleMode(tui_h_out, tui_orig_out_mode);
    if (tui_orig_out_cp != 0) SetConsoleOutputCP(tui_orig_out_cp);
}

void tui_init_term(void) {
    tui_h_out = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleMode(tui_h_out, &tui_orig_out_mode);
    SetConsoleMode(tui_h_out, tui_orig_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    tui_orig_out_cp = GetConsoleOutputCP();
    SetConsoleOutputCP(CP_UTF8);
    atexit(tui_restore_term);

    printf("\033[?1049h"); /* alternate screen buffer */
    printf("\033[?25l");
    printf("\033[2J");
    fflush(stdout);
}

/* ---- TUI: Windows chat event loop ---------------------------------------
 *
 * Same logic as tui_chat_loop in tui_posix.c, adapted for the Windows
 * event model:
 *   - WaitForMultipleObjects replaces poll(), waiting on the console
 *     input handle and a Winsock event object simultaneously.
 *   - WINDOW_BUFFER_SIZE_EVENT replaces SIGWINCH for terminal resize.
 *   - WSAEventSelect puts the socket in non-blocking mode, so incoming
 *     frames are accumulated byte-by-byte in in_frame[] (same strategy
 *     as the CLI Windows loop).
 *   - Outgoing frames may also be partially sent; the out_frame[] /
 *     out_off / out_active state machine resumes on FD_WRITE.
 *
 * The TUI drawing code is shared between platforms -- only the event
 * dispatch differs. */
void tui_chat_loop(socket_t fd, session_t *sess, int cover) {
    HANDLE      h_in;
    DWORD       h_in_mode;
    char        line[MAX_MSG + 1];
    size_t      line_len = 0;
    uint8_t     in_wire[WIRE_MAX];
    size_t      in_have           = 0;
    size_t      in_need           = WIRE_HDR; /* bytes needed for current phase */
    uint64_t    in_frame_start_ms = 0;
    uint8_t     out_frame[FRAME_SZ];
    uint8_t     out_wire[WIRE_MAX];
    uint8_t     out_next_tx[KEY];
    size_t      out_wire_len       = 0;
    size_t      out_off            = 0;
    int         out_active         = 0;
    uint64_t    out_frame_start_ms = 0;
    char        out_text[MAX_MSG + 1];
    uint8_t     plain[MAX_MSG + 1]; /* function-scope so it is wiped at exit */
    WSAEVENT    net_ev;
    const char *status     = "Secure session active  |  Ctrl+C to quit";
    int         auth_fails = 0;
    uint64_t    next_cover = cover ? GetTickCount64() + (uint64_t)cover_delay_ms() : 0;
    uint8_t     pending_msg[MAX_MSG + 1];
    uint16_t    pending_len = 0;

    if (!win_console_open(&h_in, &h_in_mode)) return;
    win_console_prepare(h_in, h_in_mode);

    memset(line, 0, sizeof line);
    memset(in_wire, 0, sizeof in_wire);
    memset(out_frame, 0, sizeof out_frame);
    memset(out_wire, 0, sizeof out_wire);
    memset(out_next_tx, 0, sizeof out_next_tx);
    memset(out_text, 0, sizeof out_text);
    memset(pending_msg, 0, sizeof pending_msg);

    /* Re-enable WINDOW_INPUT for resize events */
    {
        DWORD m;
        GetConsoleMode(h_in, &m);
        SetConsoleMode(h_in, m | ENABLE_WINDOW_INPUT);
    }

    net_ev = WSACreateEvent();
    if (net_ev == WSA_INVALID_EVENT) return;
    WSAEventSelect(fd, net_ev, FD_READ | FD_WRITE | FD_CLOSE);

    tui_draw_screen(status, line, line_len);

    while (g_running) {
        HANDLE waits[2] = {h_in, net_ev};
        DWORD  wait_ms  = POLL_INTERVAL_MS;
        if (cover) {
            int64_t remain = (int64_t)(next_cover - GetTickCount64());
            if (remain <= 0) wait_ms = 0;
            else if ((uint64_t)remain < wait_ms) wait_ms = (DWORD)remain;
        }
        DWORD wr = WaitForMultipleObjects(2, waits, FALSE, wait_ms);
        if (!g_running) break;
        if (wr == WAIT_FAILED) break;

        /* Check outgoing frame deadline on EVERY iteration — if FD_WRITE
         * stops firing (peer stops reading), the timeout check in the
         * FD_WRITE handler alone would never run. */
        if (out_active && (GetTickCount64() - out_frame_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) {
            tui_msg_add(TUI_SYSTEM, "[send timeout]");
            status = "Send timeout  |  Ctrl+C to exit";
            tui_draw_screen(status, line, line_len);
            break;
        }

        /* Incoming frame deadline: if a partial frame has been accumulating
         * for more than FRAME_TIMEOUT_S, the peer is stalling — disconnect.
         * Must be checked here (not just in FD_READ) because a peer that
         * sends a partial frame and goes silent generates no more FD_READ. */
        if (in_have > 0 && (GetTickCount64() - in_frame_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) {
            tui_msg_add(TUI_SYSTEM, "[peer stalled mid-frame]");
            status = "Peer stalled | Ctrl+C to exit";
            tui_draw_screen(status, line, line_len);
            break;
        }

        /* ----- Console input ----- */
        if (wr == WAIT_OBJECT_0) {
            INPUT_RECORD recs[CONSOLE_INPUT_RECORDS];
            DWORD        nrec = 0, i;
            if (!ReadConsoleInputA(h_in, recs, CONSOLE_INPUT_RECORDS, &nrec)) break;

            for (i = 0; i < nrec && g_running; i++) {
                if (recs[i].EventType == WINDOW_BUFFER_SIZE_EVENT) {
                    tui_draw_screen(status, line, line_len);
                    continue;
                }
                if (recs[i].EventType != KEY_EVENT) continue;
                KEY_EVENT_RECORD *k = &recs[i].Event.KeyEvent;
                if (!k->bKeyDown) continue;

                char ch = k->uChar.AsciiChar;

                if (k->wVirtualKeyCode == VK_BACK || ch == '\b') {
                    if (line_len > 0) {
                        line[--line_len] = '\0';
                        tui_draw_input(line, line_len);
                    }
                    continue;
                }
                if (k->wVirtualKeyCode == VK_RETURN || ch == '\r') {
                    if (line_len == 0) continue;

                    if (cover) {
                        /* Queue for next cover tick — all outgoing frames
                         * follow the same timing distribution. */
                        if (pending_len > 0) continue;
                        memcpy(pending_msg, line, line_len);
                        pending_len = (uint16_t)line_len;
                        tui_msg_add(TUI_ME, line);
                        crypto_wipe(line, sizeof line);
                        line_len = 0;
                        tui_draw_messages();
                        tui_draw_input(line, line_len);
                        continue;
                    }

                    if (out_active) continue;

                    if (frame_build(sess, (const uint8_t *)line, (uint16_t)line_len, out_frame, out_next_tx) != 0) {
                        crypto_wipe(line, sizeof line);
                        break;
                    }
                    out_wire_len = frame_wire_build(out_wire, out_frame);
                    crypto_wipe(out_frame, sizeof out_frame);

                    memcpy(out_text, line, line_len);
                    out_text[line_len] = '\0';
                    crypto_wipe(line, sizeof line);
                    line_len           = 0;
                    out_off            = 0;
                    out_active         = 1;
                    out_frame_start_ms = GetTickCount64();

                    {
                        int send_rc = win_try_send(fd, out_wire, out_wire_len, &out_off);
                        if (send_rc < 0) break;
                        if (send_rc == 0) {
                            memcpy(sess->tx, out_next_tx, KEY);
                            sess->tx_seq++;
                            out_active = 0;
                            tui_msg_add(TUI_ME, out_text);
                            crypto_wipe(out_wire, sizeof out_wire);
                            crypto_wipe(out_next_tx, sizeof out_next_tx);
                            crypto_wipe(out_text, sizeof out_text);
                        }
                    }
                    tui_draw_messages();
                    tui_draw_input(line, line_len);
                    continue;
                }
                if (ch >= 0x20 && ch <= 0x7E && line_len < (size_t)MAX_MSG_RATCHET) {
                    line[line_len++] = (char)ch;
                    line[line_len]   = '\0';
                    tui_draw_input(line, line_len);
                }
            }
            crypto_wipe(recs, sizeof recs); /* wipe raw keystrokes */
            /* Fall through to cover traffic check below — do NOT continue
             * back to WaitForMultipleObjects, or cover ticks get starved
             * while the user is actively typing. */
        }

        /* ----- Socket activity ----- */
        if (wr == WAIT_OBJECT_0 + 1) {
            WSANETWORKEVENTS ne;
            if (WSAEnumNetworkEvents(fd, net_ev, &ne) != 0) break;

            if (ne.lNetworkEvents & FD_READ) {
                if (in_have > 0 && (GetTickCount64() - in_frame_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) break;

                for (;;) {
                    int r = recv(fd, (char *)in_wire + in_have, (int)(in_need - in_have), 0);
                    if (r > 0) {
                        if (in_have == 0) in_frame_start_ms = GetTickCount64();
                        in_have += (size_t)r;
                        if (in_have == in_need && in_need == WIRE_HDR) {
                            /* pad_len byte received: body = frame + padding */
                            in_need = WIRE_HDR + FRAME_SZ + (size_t)in_wire[0];
                            continue; /* read body */
                        }
                        if (in_have == in_need) {
                            /* Full wire message: frame is at in_wire[WIRE_HDR] */
                            uint16_t plen  = 0;
                            int      fo_rc = frame_open(sess, in_wire + WIRE_HDR, plain, &plen);
                            if (fo_rc != 0) {
                                crypto_wipe(plain, sizeof plain);
                                crypto_wipe(in_wire, sizeof in_wire);
                                in_have           = 0;
                                in_need           = WIRE_HDR;
                                in_frame_start_ms = 0;
                                if (fo_rc == -2 || ++auth_fails >= MAX_AUTH_FAILURES) {
                                    tui_msg_add(TUI_SYSTEM, "[session error]");
                                    status = "Session error  |  Ctrl+C to exit";
                                    tui_draw_screen(status, line, line_len);
                                    goto win_tui_done;
                                }
                                break; /* back to WaitForMultipleObjects */
                            }
                            auth_fails = 0;
                            if (plen > 0) { /* len==0 is cover-traffic dummy */
                                plain[plen] = '\0';
                                sanitize_peer_text(plain, plen);
                                tui_msg_add(TUI_PEER, (char *)plain);
                                tui_draw_messages();
                                tui_draw_input(line, line_len);
                            }
                            crypto_wipe(plain, sizeof plain);
                            crypto_wipe(in_wire, sizeof in_wire);
                            in_have           = 0;
                            in_need           = WIRE_HDR;
                            in_frame_start_ms = 0;
                            break; /* one frame per event — yield to UI/cover */
                        }
                        continue;
                    }
                    if (r == 0) {
                        tui_msg_add(TUI_SYSTEM, "[peer disconnected]");
                        status = "Peer disconnected  |  Ctrl+C to exit";
                        tui_draw_screen(status, line, line_len);
                        g_running = 0;
                        goto win_tui_done;
                    }
                    if (WSAGetLastError() == WSAEWOULDBLOCK) break;
                    goto win_tui_done;
                }
            }

            if (out_active && (ne.lNetworkEvents & FD_WRITE)) {
                if ((GetTickCount64() - out_frame_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) break;
                int send_rc = win_try_send(fd, out_wire, out_wire_len, &out_off);
                if (send_rc < 0) break;
                if (send_rc == 0) {
                    memcpy(sess->tx, out_next_tx, KEY);
                    sess->tx_seq++;
                    /* All frames (real and cover) originate from cover ticks,
                     * so always schedule the next tick after completion. */
                    if (cover) next_cover = GetTickCount64() + (uint64_t)cover_delay_ms();
                    out_active = 0;
                    if (out_text[0]) {
                        tui_msg_add(TUI_ME, out_text);
                        tui_draw_messages();
                        tui_draw_input(line, line_len);
                    }
                    crypto_wipe(out_wire, sizeof out_wire);
                    crypto_wipe(out_next_tx, sizeof out_next_tx);
                    crypto_wipe(out_text, sizeof out_text);
                }
            }
            if (ne.lNetworkEvents & FD_CLOSE) {
                tui_msg_add(TUI_SYSTEM, "[peer disconnected]");
                status = "Peer disconnected  |  Ctrl+C to exit";
                tui_draw_screen(status, line, line_len);
                break;
            }
        }

        /* ---- Cover traffic: single send point for all outgoing frames.
         * Queued real messages replace the cover payload so every frame
         * follows the same timing distribution — defeating analysis. */
        if (cover && g_running && !out_active && GetTickCount64() >= next_cover) {
            const uint8_t *payload = pending_len > 0 ? pending_msg : NULL;
            uint16_t       tx_len  = pending_len;
            if (frame_build(sess, payload, tx_len, out_frame, out_next_tx) != 0) {
                tui_msg_add(TUI_SYSTEM, "cover traffic error -- session ended");
                tui_draw_screen(status, line, line_len);
                break;
            }
            out_wire_len = frame_wire_build(out_wire, out_frame);
            crypto_wipe(out_frame, sizeof out_frame);
            if (pending_len > 0) {
                crypto_wipe(pending_msg, sizeof pending_msg);
                pending_len = 0;
            }
            out_off            = 0;
            out_active         = 1;
            out_frame_start_ms = GetTickCount64();
            out_text[0]        = '\0'; /* cover frame unless overwritten above */
            {
                int send_rc = win_try_send(fd, out_wire, out_wire_len, &out_off);
                if (send_rc < 0) {
                    tui_msg_add(TUI_SYSTEM, "cover traffic error -- session ended");
                    tui_draw_screen(status, line, line_len);
                    break;
                }
                if (send_rc == 0) {
                    memcpy(sess->tx, out_next_tx, KEY);
                    sess->tx_seq++;
                    out_active = 0;
                    crypto_wipe(out_wire, sizeof out_wire);
                    crypto_wipe(out_next_tx, sizeof out_next_tx);
                    next_cover = GetTickCount64() + (uint64_t)cover_delay_ms();
                }
            }
        }
    }

win_tui_done:
    if (fd != INVALID_SOCK) WSAEventSelect(fd, nullptr, 0);
    WSACloseEvent(net_ev);
    crypto_wipe(in_wire, sizeof in_wire);
    crypto_wipe(out_frame, sizeof out_frame);
    crypto_wipe(out_wire, sizeof out_wire);
    crypto_wipe(out_next_tx, sizeof out_next_tx);
    crypto_wipe(out_text, sizeof out_text);
    crypto_wipe(line, sizeof line);
    crypto_wipe(plain, sizeof plain);
    crypto_wipe(pending_msg, sizeof pending_msg);
    win_console_restore(h_in, h_in_mode); /* restore console input mode */
    tui_msg_wipe();
}

#endif /* _WIN32 || _WIN64 */
