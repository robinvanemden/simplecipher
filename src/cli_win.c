/*
 * cli_win.c — Windows CLI console helpers and chat event loop
 *
 * This file is compiled only on Windows.  It provides:
 *   - Console open/prepare/restore helpers
 *   - win_try_send() non-blocking send helper
 *   - cli_chat_loop() using WaitForMultipleObjects
 *
 * The POSIX equivalent of cli_chat_loop() lives in cli_posix.c with the
 * same function name; only one file is compiled per platform.
 */

#include "cli.h"

#if defined(_WIN32) || defined(_WIN64)

/* ---- Windows console / socket event helpers ---------------------------- */

/* Get the interactive console input handle and remember its current mode.
 * This chat loop is intentionally console-centric on Windows: it waits on
 * the console input handle and a Winsock event object in one thread.
 * If stdin is redirected, GetConsoleMode fails and we refuse the session
 * rather than silently falling back to a less reliable code path. */
int win_console_open(HANDLE *h_in, DWORD *old_mode) {
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (h == nullptr || h == INVALID_HANDLE_VALUE) return 0;
    if (!GetConsoleMode(h, old_mode)) return 0;
    *h_in = h;
    return 1;
}

/* Keep keyboard input, drop mouse/window events.
 * We read raw KEY_EVENT records with ReadConsoleInputA(), so mouse resize
 * notifications only create useless wakeups.  Leaving PROCESSED_INPUT on
 * keeps Ctrl+C as a signal instead of a literal ^C character. */
void win_console_prepare(HANDLE h_in, DWORD old_mode) {
    DWORD mode = old_mode & ~(ENABLE_MOUSE_INPUT | ENABLE_WINDOW_INPUT);
    SetConsoleMode(h_in, mode);
}

/* Restore the console mode we inherited on startup. */
void win_console_restore(HANDLE h_in, DWORD old_mode) {
    if (h_in && h_in != INVALID_HANDLE_VALUE) SetConsoleMode(h_in, old_mode);
}

/* Write a buffer to stdout via WriteFile (bypassing libc stdio) and wipe it.
 * This avoids leaving plaintext in libc's internal stdio buffer. */
static void win_write_wipe(char *buf, size_t len) {
    DWORD w;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, (DWORD)len, &w, NULL);
    crypto_wipe(buf, len);
}

/* Erase the current local input line before printing an asynchronous event
 * (peer message, disconnect notice, auth failure, etc.).  Then the caller
 * can print the event and redraw the prompt plus any partially typed text. */
static void win_clear_input_line(size_t len) {
    char   buf[MAX_MSG + 8];
    size_t i;
    int    n;
    buf[0] = '\r';
    for (i = 0; i < len + 2 && i + 1 < sizeof buf - 1; i++) buf[i + 1] = ' ';
    buf[i + 1] = '\r';
    n          = (int)(i + 2);
    win_write_wipe(buf, (size_t)n);
}

/* Redraw the simple local prompt and the current partially typed line. */
static void win_redraw_input(const char *line, size_t len) {
    char buf[MAX_MSG + 8];
    int  n = snprintf(buf, sizeof buf, "> %.*s", (int)len, line);
    if (n < 0) n = 0;
    if (n > (int)sizeof buf - 1) n = (int)sizeof buf - 1;
    win_write_wipe(buf, (size_t)n);
}

/* Print one chat line while preserving any local text currently being typed.
 * Uses secure_chat_print to avoid leaving plaintext in libc's stdout buffer. */
static void win_print_chat(const char *who, const char *msg, const char *line, size_t line_len) {
    win_clear_input_line(line_len);
    secure_chat_print(who, msg);
    win_redraw_input(line, line_len);
}

/* Print a status line (disconnect, send error, etc.) and then restore the
 * partially typed local input line so the console stays readable. */
static void win_print_status(const char *msg, const char *line, size_t line_len) {
    char buf[MAX_MSG + 8];
    int  n;
    win_clear_input_line(line_len);
    n = snprintf(buf, sizeof buf, "%s\n", msg);
    if (n < 0) n = 0;
    if (n > (int)sizeof buf - 1) n = (int)sizeof buf - 1;
    win_write_wipe(buf, (size_t)n);
    win_redraw_input(line, line_len);
}

/* Non-blocking send helper for the WSAEventSelect loop.
 * WSAEventSelect automatically puts the socket into non-blocking mode, so a
 * single send() may accept only part of the 512-byte frame or return
 * WSAEWOULDBLOCK.  We keep the unsent tail in out_frame/out_off and resume
 * when FD_WRITE fires.  Return values:
 *   0  -- full frame sent
 *   1  -- partial frame still pending (wait for FD_WRITE)
 *  -1  -- hard send failure */
int win_try_send(socket_t fd, const uint8_t *buf, size_t len, size_t *done) {
    while (*done < len) {
        int r = send(fd, (const char *)buf + *done, (int)(len - *done), 0);
        if (r > 0) {
            *done += (size_t)r;
            continue;
        }
        if (r == 0) return -1;
        if (WSAGetLastError() == WSAEWOULDBLOCK) return 1;
        return -1;
    }
    return 0;
}

/* ---- Windows CLI chat event loop ----------------------------------------
 *
 * Why this is different from POSIX:
 *   - poll() cannot wait on both a Winsock socket and console stdin.
 *   - ReadFile() in console line mode would block after the first typed
 *     key until Enter is pressed, starving socket events mid-line.
 *
 * So Windows uses two waitable objects in one thread:
 *   waits[0] = console input handle  -> raw KEY_EVENT records
 *   waits[1] = Winsock event object  -> FD_READ / FD_WRITE / FD_CLOSE
 *
 * The socket is switched to non-blocking mode by WSAEventSelect().
 * Incoming bytes are accumulated until a full 512-byte frame is ready;
 * outgoing frames are resumed on FD_WRITE if send() could not accept the
 * full frame in one go. */
void cli_chat_loop(socket_t fd, session_t *sess, int cover) {
    HANDLE   h_in      = nullptr;
    DWORD    h_in_mode = 0;
    WSAEVENT net_ev    = WSA_INVALID_EVENT;

    if (!win_console_open(&h_in, &h_in_mode)) {
        fprintf(stderr, "Windows requires an interactive console for chat input\n");
        return;
    }
    win_console_prepare(h_in, h_in_mode);

    net_ev = WSACreateEvent();
    if (net_ev == WSA_INVALID_EVENT) {
        fprintf(stderr, "WSACreateEvent failed\n");
        win_console_restore(h_in, h_in_mode);
        return;
    }
    if (WSAEventSelect(fd, net_ev, FD_READ | FD_WRITE | FD_CLOSE) != 0) {
        fprintf(stderr, "WSAEventSelect failed\n");
        WSACloseEvent(net_ev);
        win_console_restore(h_in, h_in_mode);
        return;
    }

    {
        uint8_t  in_frame[FRAME_SZ];
        size_t   in_have           = 0;
        uint64_t in_frame_start_ms = 0; /* GetTickCount64 when first byte of
                                             * current incomplete frame arrived;
                                             * 0 means no frame in progress     */
        uint8_t  out_frame[FRAME_SZ];
        uint8_t  out_next_tx[KEY];
        size_t   out_off            = 0;
        int      out_active         = 0;
        uint64_t out_frame_start_ms = 0;
        char     out_text[MAX_MSG + 1];
        uint8_t  plain[MAX_MSG + 1]; /* function-scope so it is wiped at exit */
        char     line[MAX_MSG + 1];
        size_t   line_len   = 0;
        int      loop_error = 0;
        int      auth_fails = 0;
        uint64_t next_cover = cover ? GetTickCount64() + (uint64_t)cover_delay_ms() : 0;

        memset(in_frame, 0, sizeof in_frame);
        memset(out_frame, 0, sizeof out_frame);
        memset(out_next_tx, 0, sizeof out_next_tx);
        memset(out_text, 0, sizeof out_text);
        memset(line, 0, sizeof line);

        win_redraw_input(line, line_len);

        while (g_running) {
            HANDLE waits[2];
            DWORD  wr;

            waits[0] = h_in;
            waits[1] = net_ev;

            /* 250 ms timeout keeps Ctrl+C responsive even though Win32 wait
             * APIs are not interrupted like poll()/select() on POSIX. */
            {
                DWORD wait_ms = 250;
                if (cover) {
                    int64_t remain = (int64_t)(next_cover - GetTickCount64());
                    if (remain <= 0) wait_ms = 0;
                    else if ((uint64_t)remain < wait_ms) wait_ms = (DWORD)remain;
                }
                wr = WaitForMultipleObjects(2, waits, FALSE, wait_ms);
            }
            if (!g_running) break;
            if (wr == WAIT_FAILED) {
                loop_error = 1;
                break;
            }

            /* Check outgoing frame deadline on EVERY iteration — if FD_WRITE
             * stops firing (peer stops reading), the timeout check in the
             * FD_WRITE handler alone would never run. */
            if (out_active && (GetTickCount64() - out_frame_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) {
                win_print_status("[send timeout]", line, line_len);
                loop_error = 1;
                break;
            }

            /* Incoming frame deadline: if a partial frame has been accumulating
             * for more than FRAME_TIMEOUT_S, the peer is stalling — disconnect.
             * Must be checked here (not just in FD_READ) because a peer that
             * sends a partial frame and goes silent generates no more FD_READ. */
            if (in_have > 0 && (GetTickCount64() - in_frame_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) {
                win_print_status("[peer stalled mid-frame: disconnecting]", line, line_len);
                loop_error = 1;
                break;
            }

            /* Cover traffic: check on EVERY iteration, not just WAIT_TIMEOUT.
             * Otherwise sustained keyboard/socket events suppress cover frames. */
            if (cover && g_running && !out_active && GetTickCount64() >= next_cover) {
                if (frame_build(sess, NULL, 0, out_frame, out_next_tx) != 0) {
                    win_print_status("[cover traffic error -- session ended]", line, line_len);
                    loop_error = 1;
                    break;
                }
                out_off            = 0;
                out_active         = 1;
                out_frame_start_ms = GetTickCount64();
                out_text[0]        = '\0'; /* mark as cover frame */
                {
                    int send_rc = win_try_send(fd, out_frame, FRAME_SZ, &out_off);
                    if (send_rc < 0) {
                        win_print_status("[cover traffic error -- session ended]", line, line_len);
                        loop_error = 1;
                        break;
                    }
                    if (send_rc == 0) {
                        memcpy(sess->tx, out_next_tx, KEY);
                        sess->tx_seq++;
                        out_active = 0;
                        crypto_wipe(out_frame, sizeof out_frame);
                        crypto_wipe(out_next_tx, sizeof out_next_tx);
                        next_cover = GetTickCount64() + (uint64_t)cover_delay_ms();
                    }
                }
            }

            if (wr == WAIT_TIMEOUT) continue;

            /* ----- Local keyboard input ----- */
            if (wr == WAIT_OBJECT_0) {
                INPUT_RECORD recs[32];
                DWORD        nrec = 0;
                DWORD        i;

                if (!ReadConsoleInputA(h_in, recs, 32, &nrec)) {
                    loop_error = 1;
                    break;
                }

                for (i = 0; i < nrec && g_running; i++) {
                    KEY_EVENT_RECORD *k;
                    char              ch;
                    int               send_rc;

                    if (recs[i].EventType != KEY_EVENT) continue;
                    k = &recs[i].Event.KeyEvent;
                    if (!k->bKeyDown) continue;

                    if (k->wVirtualKeyCode == VK_BACK || k->uChar.AsciiChar == '\b') {
                        if (line_len > 0) {
                            char  bs[3] = {'\b', ' ', '\b'};
                            DWORD bsw;
                            line[--line_len] = '\0';
                            WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), bs, 3, &bsw, NULL);
                        }
                        continue;
                    }

                    if (k->wVirtualKeyCode == VK_RETURN || k->uChar.AsciiChar == '\r') {
                        {
                            char  nl = '\n';
                            DWORD nlw;
                            WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &nl, 1, &nlw, NULL);
                        }

                        if (line_len == 0) {
                            win_redraw_input(line, line_len);
                            continue;
                        }
                        if (out_active) {
                            win_print_status("[send still in progress -- press Enter again shortly]", line, line_len);
                            continue;
                        }

                        if (frame_build(sess, (const uint8_t *)line, (uint16_t)line_len, out_frame, out_next_tx) != 0) {
                            loop_error = 1;
                            break;
                        }
                        memcpy(out_text, line, line_len);
                        out_text[line_len] = '\0';
                        crypto_wipe(line, sizeof line);
                        line_len           = 0;
                        out_off            = 0;
                        out_active         = 1;
                        out_frame_start_ms = GetTickCount64();

                        send_rc = win_try_send(fd, out_frame, FRAME_SZ, &out_off);
                        if (send_rc < 0) {
                            win_print_status("[send error]", line, line_len);
                            loop_error = 1;
                            break;
                        }
                        if (send_rc == 0) {
                            memcpy(sess->tx, out_next_tx, KEY);
                            sess->tx_seq++;
                            /* Cover timer NOT reset on real sends — schedule runs independently
                             * so real messages blend into the cover traffic pattern. */
                            out_active = 0;
                            win_print_chat(" me", out_text, line, line_len);
                            crypto_wipe(out_frame, sizeof out_frame);
                            crypto_wipe(out_next_tx, sizeof out_next_tx);
                            crypto_wipe(out_text, sizeof out_text);
                        } else {
                            win_redraw_input(line, line_len);
                        }
                        continue;
                    }

                    ch = k->uChar.AsciiChar;
                    if (ch >= 0x20 && ch <= 0x7E) {
                        if (line_len < (size_t)MAX_MSG_RATCHET) {
                            DWORD chw;
                            line[line_len++] = ch;
                            line[line_len]   = '\0';
                            WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &ch, 1, &chw, NULL);
                        }
                        continue;
                    }
                }
                crypto_wipe(recs, sizeof recs); /* wipe raw keystrokes */
                if (loop_error) break;
                continue;
            }

            /* ----- Socket activity: incoming data, writable socket, close ----- */
            if (wr == WAIT_OBJECT_0 + 1) {
                WSANETWORKEVENTS ne;

                if (WSAEnumNetworkEvents(fd, net_ev, &ne) != 0) {
                    loop_error = 1;
                    break;
                }

                if (ne.lNetworkEvents & FD_READ) {
                    /* Accumulate incoming bytes until a full 512-byte frame arrives.
                     * WSAEventSelect puts the socket in non-blocking mode, so recv()
                     * returns WSAEWOULDBLOCK when no more bytes are available right now.
                     * We loop here to drain everything the OS has buffered before
                     * returning to WaitForMultipleObjects.
                     *
                     * Partial-frame timeout: if the first byte of a frame arrives but
                     * the rest does not arrive within 30 seconds, we disconnect.  This
                     * mirrors the POSIX SO_RCVTIMEO strategy and prevents a post-SAS
                     * peer from stalling the Windows event loop indefinitely by sending
                     * a partial frame and then going silent. */

                    /* Check deadline before reading: disconnect if a frame has been
                     * partially received for more than 30 seconds. */
                    if (in_have > 0 && (GetTickCount64() - in_frame_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) {
                        win_print_status("[peer stalled mid-frame: disconnecting]", line, line_len);
                        loop_error = 1;
                        break;
                    }

                    for (;;) {
                        int r = recv(fd, (char *)in_frame + in_have, (int)(FRAME_SZ - in_have), 0);
                        if (r > 0) {
                            /* Record when the first byte of this frame arrived. */
                            if (in_have == 0) in_frame_start_ms = GetTickCount64();
                            in_have += (size_t)r;
                            if (in_have == FRAME_SZ) {
                                uint16_t plen = 0;

                                int fo_rc = frame_open(sess, in_frame, plain, &plen);
                                if (fo_rc != 0) {
                                    crypto_wipe(plain, sizeof plain);
                                    crypto_wipe(in_frame, sizeof in_frame);
                                    in_have           = 0;
                                    in_frame_start_ms = 0;
                                    if (fo_rc == -2 || ++auth_fails >= MAX_AUTH_FAILURES) {
                                        win_print_status("[session error: authentication or sequence failure]", line,
                                                         line_len);
                                        loop_error = 1;
                                        break;
                                    }
                                    continue;
                                }
                                auth_fails = 0;
                                if (plen > 0) { /* len==0 is cover-traffic dummy */
                                    plain[plen] = '\0';
                                    sanitize_peer_text(plain, plen);
                                    win_print_chat("peer", (char *)plain, line, line_len);
                                }
                                crypto_wipe(plain, sizeof plain);
                                crypto_wipe(in_frame, sizeof in_frame);
                                in_have           = 0;
                                in_frame_start_ms = 0; /* frame complete; reset timer */
                                continue;
                            }
                            continue;
                        }
                        if (r == 0) {
                            win_print_status("[peer disconnected]", line, line_len);
                            g_running = 0;
                            break;
                        }
                        if (WSAGetLastError() == WSAEWOULDBLOCK) break;
                        win_print_status("[peer disconnected]", line, line_len);
                        loop_error = 1;
                        break;
                    }
                    if (loop_error || !g_running) break;
                }

                if (out_active && (ne.lNetworkEvents & FD_WRITE)) {
                    /* Deadline: abort if partial send pending too long. */
                    if ((GetTickCount64() - out_frame_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000) {
                        win_print_status("[send timeout]", line, line_len);
                        loop_error = 1;
                        break;
                    }
                    int send_rc = win_try_send(fd, out_frame, FRAME_SZ, &out_off);
                    if (send_rc < 0) {
                        win_print_status("[send error]", line, line_len);
                        loop_error = 1;
                        break;
                    }
                    if (send_rc == 0) {
                        memcpy(sess->tx, out_next_tx, KEY);
                        sess->tx_seq++;
                        /* Reset cover timer only for cover frames (out_text[0]==0).
                         * Real message sends must NOT reset the timer — otherwise an
                         * attacker forcing backpressure can correlate cover timing with
                         * real user traffic. */
                        if (cover && !out_text[0]) next_cover = GetTickCount64() + (uint64_t)cover_delay_ms();
                        out_active = 0;
                        /* out_text[0]==0 means this was a cover frame — no UI update */
                        if (out_text[0]) win_print_chat(" me", out_text, line, line_len);
                        crypto_wipe(out_frame, sizeof out_frame);
                        crypto_wipe(out_next_tx, sizeof out_next_tx);
                        crypto_wipe(out_text, sizeof out_text);
                    }
                }

                if (ne.lNetworkEvents & FD_CLOSE) {
                    win_print_status("[peer disconnected]", line, line_len);
                    break;
                }
                continue;
            }

            loop_error = 1;
            break;
        }

        crypto_wipe(in_frame, sizeof in_frame);
        crypto_wipe(out_frame, sizeof out_frame);
        crypto_wipe(out_next_tx, sizeof out_next_tx);
        crypto_wipe(out_text, sizeof out_text);
        crypto_wipe(line, sizeof line);
        crypto_wipe(plain, sizeof plain);
    }

    if (fd != INVALID_SOCK) WSAEventSelect(fd, nullptr, 0);
    WSACloseEvent(net_ev);
    win_console_restore(h_in, h_in_mode);
}

#endif /* _WIN32 || _WIN64 */
