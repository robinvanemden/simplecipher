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
    uint8_t     in_frame[FRAME_SZ];
    size_t      in_have           = 0;
    uint64_t    in_frame_start_ms = 0;
    uint8_t     out_frame[FRAME_SZ];
    uint8_t     out_next_tx[KEY];
    size_t      out_off    = 0;
    int         out_active = 0;
    char        out_text[MAX_MSG + 1];
    WSAEVENT    net_ev;
    const char *status     = "Secure session active  |  Ctrl+C to quit";
    int         auth_fails = 0;
    uint64_t    next_cover = cover ? GetTickCount64() + (uint64_t)cover_delay_ms() : 0;

    if (!win_console_open(&h_in, &h_in_mode)) return;
    win_console_prepare(h_in, h_in_mode);

    memset(line, 0, sizeof line);
    memset(in_frame, 0, sizeof in_frame);
    memset(out_frame, 0, sizeof out_frame);
    memset(out_next_tx, 0, sizeof out_next_tx);
    memset(out_text, 0, sizeof out_text);

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
        DWORD  wait_ms  = 250;
        if (cover) {
            int64_t remain = (int64_t)(next_cover - GetTickCount64());
            if (remain <= 0) wait_ms = 0;
            else if ((uint64_t)remain < wait_ms) wait_ms = (DWORD)remain;
        }
        DWORD wr = WaitForMultipleObjects(2, waits, FALSE, wait_ms);
        if (!g_running) break;
        if (wr == WAIT_FAILED) break;

        /* ----- Console input ----- */
        if (wr == WAIT_OBJECT_0) {
            INPUT_RECORD recs[32];
            DWORD        nrec = 0, i;
            if (!ReadConsoleInputA(h_in, recs, 32, &nrec)) break;

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
                    if (out_active) continue;

                    if (frame_build(sess, (const uint8_t *)line, (uint16_t)line_len, out_frame, out_next_tx) != 0) {
                        crypto_wipe(line, sizeof line);
                        break;
                    }

                    memcpy(out_text, line, line_len);
                    out_text[line_len] = '\0';
                    crypto_wipe(line, sizeof line);
                    line_len   = 0;
                    out_off    = 0;
                    out_active = 1;

                    {
                        int send_rc = win_try_send(fd, out_frame, FRAME_SZ, &out_off);
                        if (send_rc < 0) break;
                        if (send_rc == 0) {
                            memcpy(sess->tx, out_next_tx, KEY);
                            sess->tx_seq++;
                            if (cover) next_cover = GetTickCount64() + (uint64_t)cover_delay_ms();
                            out_active = 0;
                            tui_msg_add(TUI_ME, out_text);
                            crypto_wipe(out_frame, sizeof out_frame);
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
            continue;
        }

        /* ----- Socket activity ----- */
        if (wr == WAIT_OBJECT_0 + 1) {
            WSANETWORKEVENTS ne;
            if (WSAEnumNetworkEvents(fd, net_ev, &ne) != 0) break;

            if (ne.lNetworkEvents & FD_READ) {
                if (in_have > 0 && (GetTickCount64() - in_frame_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) break;

                for (;;) {
                    int r = recv(fd, (char *)in_frame + in_have, (int)(FRAME_SZ - in_have), 0);
                    if (r > 0) {
                        if (in_have == 0) in_frame_start_ms = GetTickCount64();
                        in_have += (size_t)r;
                        if (in_have == FRAME_SZ) {
                            uint8_t  plain[MAX_MSG + 1];
                            uint16_t plen  = 0;
                            int      fo_rc = frame_open(sess, in_frame, plain, &plen);
                            if (fo_rc != 0) {
                                crypto_wipe(plain, sizeof plain);
                                crypto_wipe(in_frame, sizeof in_frame);
                                in_have = 0;
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
                            crypto_wipe(in_frame, sizeof in_frame);
                            in_have           = 0;
                            in_frame_start_ms = 0;
                            continue;
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
                int send_rc = win_try_send(fd, out_frame, FRAME_SZ, &out_off);
                if (send_rc < 0) break;
                if (send_rc == 0) {
                    memcpy(sess->tx, out_next_tx, KEY);
                    sess->tx_seq++;
                    if (cover) next_cover = GetTickCount64() + (uint64_t)cover_delay_ms();
                    out_active = 0;
                    /* out_text[0]==0 means this was a cover frame — no UI update */
                    if (out_text[0]) {
                        tui_msg_add(TUI_ME, out_text);
                        tui_draw_messages();
                        tui_draw_input(line, line_len);
                    }
                    crypto_wipe(out_frame, sizeof out_frame);
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

        /* ---- Cover traffic: send encrypted dummy frame on schedule ---- */
        if (cover && g_running && !out_active && GetTickCount64() >= next_cover) {
            if (frame_build(sess, NULL, 0, out_frame, out_next_tx) != 0) break;
            out_off     = 0;
            out_active  = 1;
            out_text[0] = '\0'; /* mark as cover frame */
            {
                int send_rc = win_try_send(fd, out_frame, FRAME_SZ, &out_off);
                if (send_rc < 0) break;
                if (send_rc == 0) {
                    memcpy(sess->tx, out_next_tx, KEY);
                    sess->tx_seq++;
                    out_active = 0;
                    crypto_wipe(out_frame, sizeof out_frame);
                    crypto_wipe(out_next_tx, sizeof out_next_tx);
                    next_cover = GetTickCount64() + (uint64_t)cover_delay_ms();
                }
                /* send_rc == 1: partial send; FD_WRITE will complete it */
            }
        }
    }

win_tui_done:
    if (fd != INVALID_SOCK) WSAEventSelect(fd, nullptr, 0);
    WSACloseEvent(net_ev);
    crypto_wipe(in_frame, sizeof in_frame);
    crypto_wipe(out_frame, sizeof out_frame);
    crypto_wipe(out_next_tx, sizeof out_next_tx);
    crypto_wipe(out_text, sizeof out_text);
    crypto_wipe(line, sizeof line);
    tui_msg_wipe();
}

#endif /* _WIN32 || _WIN64 */
