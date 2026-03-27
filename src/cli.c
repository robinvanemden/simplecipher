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
    char t[16];
    char buf[MAX_MSG + 64]; /* message + timestamp + label + formatting */
    int  n;
    ts(t, sizeof t);
    n = snprintf(buf, sizeof buf, "[%s] %s: %s\n", t, label, msg);
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
