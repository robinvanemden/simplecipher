/*
 * cli.c — Shared CLI code for SimpleCipher
 *
 * Implements secure_chat_print(), which formats a timestamped chat line
 * and writes it directly to the OS (bypassing libc's stdio buffer) to
 * prevent plaintext from lingering in memory.
 */

#include "cli.h"

/* Write a formatted chat line to stdout without leaving plaintext in
 * libc's stdio buffer.
 *
 * printf/fprintf copy their formatted output into an internal buffer
 * (typically 4096 bytes) that is never wiped.  By formatting into a
 * stack buffer, writing it directly with the OS write syscall, and then
 * wiping the buffer, we ensure no plaintext copy persists in libc.
 *
 * The format is: [HH:MM:SS] label: message\n */
void secure_chat_print(const char *label, const char *msg) {
    char t[TIMESTAMP_BUF];
    char buf[MAX_MSG + 96]; /* message + timestamp + label + ANSI color codes */
    int  n;
    /* Color-code labels so peer messages are visually distinct from local
     * ones.  Peer text is sanitized (0x20-0x7E only) so a malicious peer
     * cannot inject escape codes to spoof the color. */
    const char *color_on  = "";
    const char *color_off = "";
    if (strncmp(label, "peer", 4) == 0) {
        color_on  = "\033[36m";
        color_off = "\033[0m";
    } else if (strncmp(label, "sys", 3) == 0) {
        color_on  = "\033[33m";
        color_off = "\033[0m";
    }
    format_timestamp(t, sizeof t);
    n = snprintf(buf, sizeof buf, "[%s] %s%s%s: %s\n", t, color_on, label, color_off, msg);
    if (n < 0) n = 0;
    if (n > (int)sizeof buf - 1) n = (int)sizeof buf - 1;
#if defined(_WIN32) || defined(_WIN64)
    {
        DWORD w;
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, (DWORD)n, &w, nullptr);
    }
#else
    {
        ssize_t r;
        do { r = write(STDOUT_FILENO, buf, (size_t)n); } while (r < 0 && errno == EINTR);
    }
#endif
    crypto_wipe(buf, sizeof buf);
}
