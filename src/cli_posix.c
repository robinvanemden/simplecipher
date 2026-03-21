/*
 * cli_posix.c — POSIX CLI chat event loop for SimpleCipher
 *
 * This file is compiled only on POSIX systems (Linux, macOS, BSD).
 * It provides cli_chat_loop() using poll() on the socket and stdin.
 *
 * The Windows equivalent lives in cli_win.c with the same function name;
 * only one file is compiled per platform.
 */

#include "cli.h"

#ifndef _WIN32

/* POSIX: poll() on socket (fds[0]) and stdin (fds[1]). */
void cli_chat_loop(socket_t fd, session_t *sess){
    while (g_running){
        struct pollfd fds[2];
        uint8_t frame[FRAME_SZ];
        uint8_t next_tx[KEY];
        uint8_t plain[MAX_MSG + 1];
        char    line[MAX_MSG + 2];
        uint16_t plen;
        int      ready;

        fds[0].fd     = fd;
        fds[0].events = POLLIN;
        fds[1].fd     = STDIN_FILENO;
        fds[1].events = POLLIN;

        /* Block until socket or stdin has data.
         * EINTR means a signal fired -- recheck g_running and loop. */
        ready = poll(fds, 2, -1);
        if (ready < 0){
            if (errno == EINTR) continue;
            break;
        }

        /* ----- Incoming encrypted frame from peer ----- */
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)){
            if (read_exact(fd, frame, FRAME_SZ) != 0){
                printf("[peer disconnected]\n");
                break;
            }
            plen = 0;
            if (frame_open(sess, frame, plain, &plen) != 0){
                fprintf(stderr, "[session error: authentication or sequence failure]\n");
                break;
            }
            plain[plen] = '\0';
            sanitize_peer_text(plain, plen);  /* strip terminal escape bytes */
            secure_chat_print("peer", (char*)plain);
            crypto_wipe(plain, sizeof plain);
            crypto_wipe(frame, sizeof frame);
        }

        /* ----- Outgoing message typed by the user ----- */
        if (g_running && (fds[1].revents & POLLIN)){
            /* read() instead of fgets() to bypass libc's stdin buffer.
             * fgets copies user input into an internal ~4KB buffer that is
             * never wiped; read() goes straight from kernel to our buffer.
             * In cooked (canonical) mode the terminal driver still handles
             * line editing (backspace, Ctrl+U, etc.) and delivers a complete
             * line when the user presses Enter. */
            ssize_t rn = read(STDIN_FILENO, line, sizeof line - 1);
            if (rn <= 0) break;
            size_t n = (size_t)rn;
            line[n] = '\0';
            if (n > 0 && line[n-1] == '\n') line[--n] = '\0';
            if (n == 0){ crypto_wipe(line, sizeof line); continue; }
            if (n > (size_t)MAX_MSG){
                printf("[too long -- max %d bytes]\n", MAX_MSG);
                crypto_wipe(line, sizeof line);
                continue;
            }

            /* Build the frame (compute next_chain) but do not advance
             * the chain yet -- only commit after a successful write. */
            if (frame_build(sess->tx, sess->tx_seq,
                            (const uint8_t*)line, (uint16_t)n,
                            frame, next_tx) != 0){
                crypto_wipe(line,    sizeof line);
                crypto_wipe(frame,   sizeof frame);
                crypto_wipe(next_tx, sizeof next_tx);
                break;
            }

            if (write_exact(fd, frame, FRAME_SZ) != 0){
                fprintf(stderr, "[send error]\n");
                crypto_wipe(line,    sizeof line);
                crypto_wipe(frame,   sizeof frame);
                crypto_wipe(next_tx, sizeof next_tx);
                break;
            }

            /* Write succeeded -- now commit the chain advance. */
            memcpy(sess->tx, next_tx, KEY);
            sess->tx_seq++;

            secure_chat_print(" me", line);

            crypto_wipe(line,    sizeof line);
            crypto_wipe(frame,   sizeof frame);
            crypto_wipe(next_tx, sizeof next_tx);
        }
    }
}

#endif /* !_WIN32 */
