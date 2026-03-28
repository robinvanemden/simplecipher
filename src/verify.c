/*
 * verify.c — Human-facing identity verification for SimpleCipher
 *
 * Implementation of passphrase input, key generation, fingerprint
 * checking, and CLI-mode SAS ceremony.  See verify.h for the API.
 */

#include "verify.h"
#include "args.h"
#include "tui.h"

#if defined(_WIN32) || defined(_WIN64)
#    include <io.h>    /* _read — bypass libc FILE* buffer for SAS input */
#    include <conio.h> /* _getch — read passphrase without echo */
#else
#    include <termios.h> /* tcgetattr/tcsetattr — disable echo for passphrase */
#    include <fcntl.h>   /* open /dev/tty */
#    include <poll.h>    /* poll — multiplex stdin + peer socket */
#endif

/* Read a passphrase from /dev/tty (POSIX) or console (Windows) with
 * echo disabled.  Returns length, or -1 on error.  The caller must
 * wipe buf after use. */
int read_passphrase(const char *prompt, char *buf, size_t bufsz) {
#if defined(_WIN32) || defined(_WIN64)
    (void)!_write(2, prompt, (unsigned)strlen(prompt));
    int i = 0;
    while (i < (int)bufsz - 1) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') break;
        if (ch == '\b' || ch == 127) {
            if (i > 0) i--;
            continue;
        }
        buf[i++] = (char)ch;
    }
    buf[i] = '\0';
    (void)!_write(2, "\n", 1);
    return i;
#else
    (void)!write(STDERR_FILENO, prompt, strlen(prompt));
    struct termios old, raw;
    int            fd = open("/dev/tty", O_RDWR);
    if (fd < 0) fd = STDIN_FILENO;
    tcgetattr(fd, &old);
    raw = old;
    raw.c_lflag &= ~((tcflag_t)ECHO);
    tcsetattr(fd, TCSANOW, &raw);

    int i = 0;
    while (i < (int)bufsz - 1) {
        char    ch;
        ssize_t r = read(fd, &ch, 1);
        if (r <= 0 || ch == '\n') break;
        buf[i++] = ch;
    }
    buf[i] = '\0';

    tcsetattr(fd, TCSANOW, &old);
    if (fd != STDIN_FILENO) close(fd);
    (void)!write(STDERR_FILENO, "\n", 1);
    return i;
#endif
}

/* Strip dashes and uppercase a hex string for comparison.
 * Returns the number of characters written to out (excluding NUL).
 * The caller must wipe out after use. */
int normalize_hex(const char *in, char *out, size_t out_sz) {
    int j = 0;
    for (int i = 0; in[i] && j < (int)out_sz - 1; i++) {
        char c = in[i];
        if (c == '-') continue;
        if (c >= 'a' && c <= 'z') c -= 32;
        out[j++] = c;
    }
    out[j] = '\0';
    return j;
}

/* Handle the keygen subcommand: generate a passphrase-protected identity key. */
int keygen_main(const char *path) {
    char pass1[256], pass2[256];
    int  p1 = read_passphrase("  Enter passphrase: ", pass1, sizeof pass1);
    if (p1 <= 0) {
        fprintf(stderr, "  Empty passphrase not allowed.\n");
        return EXIT_USAGE;
    }
    if (p1 >= (int)sizeof(pass1) - 1) {
        crypto_wipe(pass1, sizeof pass1);
        fprintf(stderr, "  Passphrase too long (max 255 characters).\n");
        return EXIT_USAGE;
    }
    int p2       = read_passphrase("  Confirm passphrase: ", pass2, sizeof pass2);
    int mismatch = (p1 != p2) || (memcmp(pass1, pass2, (size_t)p1) != 0);
    crypto_wipe(pass2, sizeof pass2);
    if (mismatch) {
        crypto_wipe(pass1, sizeof pass1);
        fprintf(stderr, "  Passphrases do not match.\n");
        return EXIT_USAGE;
    }

    uint8_t priv[KEY], pub[KEY];
    gen_keypair(priv, pub);

    int rc_save = identity_save(path, priv, pass1, (size_t)p1);
    crypto_wipe(pass1, sizeof pass1);

    if (rc_save != 0) {
        crypto_wipe(priv, sizeof priv);
        fprintf(stderr, "  Failed to write %s\n", path);
        return EXIT_INTERNAL;
    }

    char fp[20];
    format_fingerprint(fp, pub);
    printf("  Identity key saved to %s\n", path);
    printf("  Your fingerprint: %s\n", fp);
    printf("  (share with your peer on paper — same every time you load this key)\n");

    crypto_wipe(priv, sizeof priv);
    crypto_wipe(fp, sizeof fp);
    return EXIT_OK;
}

/* Verify the peer's public key fingerprint against the expected value.
 * Returns 0 if OK (or no fingerprint expected), -1 on mismatch. */
int verify_peer_fingerprint(const uint8_t peer_pub[KEY], const char *expected, int tui_mode) {
    char peer_fp[20];
    format_fingerprint(peer_fp, peer_pub);

    if (expected) {
        char ne[20] = {0}, np[20] = {0};
        int  ei       = normalize_hex(expected, ne, sizeof ne);
        int  pi       = normalize_hex(peer_fp, np, sizeof np);
        int  mismatch = (ei != pi) || ct_compare((const uint8_t *)ne, (const uint8_t *)np, (size_t)ei) != 0;
        crypto_wipe(ne, sizeof ne);
        crypto_wipe(np, sizeof np);
        if (mismatch) {
            if (tui_mode) tui_restore_term();
            fprintf(stderr,
                    "\n  [!] Peer fingerprint mismatch!\n"
                    "  Expected: %s\n"
                    "  Got:      %s\n"
                    "  Aborting -- possible MITM attack.\n",
                    expected, peer_fp);
            crypto_wipe(peer_fp, sizeof peer_fp);
            return -1;
        }
        if (!tui_mode) printf("  Peer fingerprint verified: %s\n", peer_fp);
    }
    crypto_wipe(peer_fp, sizeof peer_fp);
    return 0;
}

/* CLI-mode SAS verification: display the safety code box, read user input
 * with peer-disconnect detection, compare typed code against expected.
 *
 * Returns EXIT_OK (0) on match, EXIT_MITM (4) on mismatch,
 * EXIT_ABORT (7) on timeout/cancel/Ctrl+C/Ctrl+D,
 * EXIT_NET (2) on peer disconnect. */
int cli_sas_verify(const char *sas, socket_t fd) {
    char typed_sas[16] = {0};

    printf("\n");
    printf("  +----------------------------------------------+\n");
    printf("  |                                              |\n");
    printf("  |              SAFETY CODE                     |\n");
    /* write() instead of printf to keep SAS out of libc's stdio buffer */
    {
        char sas_line[64];
        int  sn = snprintf(sas_line, sizeof sas_line, "  |              %-9s                        |\n", sas);
        if (sn > 0) {
            fflush(stdout);
            ssize_t wr;
            do { wr = write(STDOUT_FILENO, sas_line, (size_t)sn); } while (wr < 0 && errno == EINTR);
            crypto_wipe(sas_line, sizeof sas_line);
        }
    }
    printf("  |                                              |\n");
    printf("  |  Compare this code with your peer over a     |\n");
    printf("  |  separate channel (phone call, in person).   |\n");
    printf("  |                                              |\n");
    printf("  |  Match?    Type the full code below.         |\n");
    printf("  |  Mismatch? Press Ctrl+C -- you're being      |\n");
    printf("  |            intercepted.                      |\n");
    printf("  |                                              |\n");
    printf("  |  Fingerprint = identity (pre-shared).        |\n");
    printf("  |  Safety code = this session (compare now).   |\n");
    printf("  |                                              |\n");
    printf("  +----------------------------------------------+\n");
    printf("\n");

    /* Require the user to type the full safety code (all 9 characters
     * including the dash) rather than just the first 4.  Typing only a
     * prefix collapses the practical verification from 32 bits to 16 bits
     * because users tend to focus only on the part they must enter. */
    printf("  Confirm (type full code): ");
    fflush(stdout);

    /* read() instead of fgets() so the typed code never passes through
     * libc's internal ~4KB FILE* buffer (which is never wiped).  In
     * canonical mode, read() returns a complete line from the kernel.
     * On Windows, _read() serves the same purpose.
     *
     * Both POSIX and Windows paths monitor the peer socket alongside
     * stdin so a peer disconnect during SAS verification is detected
     * immediately instead of leaving the user stuck. */
    {
#if defined(_WIN32) || defined(_WIN64)
        /* Loop with 1-second waits so Ctrl+C (which sets g_running=0
         * from the console handler thread) is detected promptly.
         * Also watches peer socket for disconnect and enforces 5-min deadline. */
        HANDLE   h_stdin    = GetStdHandle(STD_INPUT_HANDLE);
        WSAEVENT sas_ev     = WSACreateEvent();
        uint64_t sas_dl_win = GetTickCount64() + 300000;
        int      rn         = -1;
        WSAEventSelect(fd, sas_ev, FD_CLOSE);
        {
            HANDLE sas_waits[2] = {h_stdin, sas_ev};
            while (g_running) {
                uint64_t now_w = GetTickCount64();
                if (now_w >= sas_dl_win) {
                    printf("SAS verification timed out.\n");
                    WSAEventSelect(fd, sas_ev, 0);
                    WSACloseEvent(sas_ev);
                    crypto_wipe(typed_sas, sizeof typed_sas);
                    return EXIT_ABORT;
                }
                DWORD wr = WaitForMultipleObjects(2, sas_waits, FALSE, 1000);
                if (wr == WAIT_OBJECT_0 + 1) {
                    fprintf(stderr, "Peer disconnected during SAS verification.\n");
                    WSAEventSelect(fd, sas_ev, 0);
                    WSACloseEvent(sas_ev);
                    crypto_wipe(typed_sas, sizeof typed_sas);
                    return EXIT_NET;
                }
                if (wr == WAIT_OBJECT_0) {
                    rn = _read(0, typed_sas, (unsigned)(sizeof typed_sas - 1));
                    break;
                }
                /* WAIT_TIMEOUT: loop back, recheck g_running + deadline */
            }
        }
        WSAEventSelect(fd, sas_ev, 0);
        WSACloseEvent(sas_ev);
        if (!g_running) {
            printf("Aborted.\n");
            crypto_wipe(typed_sas, sizeof typed_sas);
            return EXIT_ABORT;
        }
#else
        ssize_t rn = -1;
        {
            struct pollfd sas_fds[2]   = {{STDIN_FILENO, POLLIN, 0}, {fd, 0, 0}};
            uint64_t      sas_deadline = monotonic_ms() + 300000; /* 5-minute timeout */
            while (g_running) {
                int64_t remain = (int64_t)(sas_deadline - monotonic_ms());
                if (remain <= 0) {
                    printf("SAS verification timed out.\n");
                    crypto_wipe(typed_sas, sizeof typed_sas);
                    return EXIT_ABORT;
                }
                int poll_ms = remain > 1000 ? 1000 : (int)remain;
                int pr      = poll(sas_fds, 2, poll_ms);
                if (pr < 0 && errno == EINTR) continue;
                if (pr < 0) break;
                if (sas_fds[1].revents & (POLLHUP | POLLERR)) {
                    fprintf(stderr, "Peer disconnected during SAS verification.\n");
                    crypto_wipe(typed_sas, sizeof typed_sas);
                    return EXIT_NET;
                }
                if (sas_fds[0].revents & POLLIN) {
                    rn = read(STDIN_FILENO, typed_sas, sizeof typed_sas - 1);
                    break;
                }
            }
            if (!g_running) { /* Ctrl+C or signal */
                printf("Aborted.\n");
                crypto_wipe(typed_sas, sizeof typed_sas);
                return EXIT_ABORT;
            }
        }
#endif
        if (rn <= 0) {
            printf("Aborted.\n");
            crypto_wipe(typed_sas, sizeof typed_sas);
            return EXIT_ABORT;
        }
        typed_sas[rn] = '\0';
    }
    /* Drain any leftover characters in the kernel's line buffer (e.g.
     * user pasted a long string).  Without this, the extra bytes end
     * up as the first "message" in the chat. */
    if (!strchr(typed_sas, '\n')) {
        char drain;
#if defined(_WIN32) || defined(_WIN64)
        int dr;
        do { dr = _read(0, &drain, 1); } while (dr == 1 && drain != '\n');
#else
        ssize_t dr;
        do { dr = read(STDIN_FILENO, &drain, 1); } while (dr == 1 && drain != '\n');
#endif
    }
    /* Strip trailing newline, normalize (strip dashes, uppercase), then
     * compare.  Accepts "A3F2-91BC", "A3F291BC", "a3f291bc" etc.  Full
     * comparison ensures the user verifies all 32 bits, not just 16. */
    {
        size_t yl = strlen(typed_sas);
        if (yl > 0 && typed_sas[yl - 1] == '\n') typed_sas[yl - 1] = '\0';
    }
    {
        /* Strip dashes and uppercase both strings before comparing. */
        char nt[16] = {0}, ns[16] = {0};
        int  ti       = normalize_hex(typed_sas, nt, sizeof nt);
        int  si       = normalize_hex(sas, ns, sizeof ns);
        int  mismatch = (ti != si || ct_compare((const uint8_t *)nt, (const uint8_t *)ns, (size_t)ti) != 0);
        crypto_wipe(nt, sizeof nt);
        crypto_wipe(ns, sizeof ns);
        crypto_wipe(typed_sas, sizeof typed_sas);
        if (mismatch) {
            printf("\n  Code mismatch -- aborted.\n");
            return EXIT_MITM;
        }
    }
    return EXIT_OK;
}
