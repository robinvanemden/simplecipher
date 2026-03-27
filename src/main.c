/*
 * main.c — Entry point for SimpleCipher
 *
 * START READING HERE.
 *
 * SimpleCipher is a peer-to-peer encrypted chat tool.  No server, no
 * accounts -- just two people on a TCP connection with X25519 key exchange
 * and XChaCha20-Poly1305 encryption.
 *
 * RECOMMENDED READING ORDER
 * =========================
 *   1. main.c        (this file)   — session lifecycle, arg parsing
 *   2. protocol.h    — wire format, frame layout, session key derivation
 *   3. crypto.h      — cryptographic building blocks (KDF, ratchet, SAS)
 *   4. ratchet.h     — DH ratchet for post-compromise security
 *   5. network.h     — TCP socket I/O
 *   6. tui.h / cli.h — user interface event loops
 *   7. platform.h    — OS abstraction (sockets, RNG, signals)
 *
 * READING PATHS BY AUDIENCE
 * =========================
 *   Undergrad (C + crypto):
 *     main.c → protocol.h → crypto.h/c → ratchet.h/c → network.h
 *     Skip: platform.c hardening, event loop internals, cover traffic
 *
 *   Crypto student (Double Ratchet):
 *     ratchet.h/c → crypto.h/c → protocol.c frame_build/frame_open
 *     These ~500 lines contain the complete Double Ratchet implementation
 *
 *   Security auditor:
 *     platform.h/c (seccomp/Capsicum/pledge) → network.c (deadline I/O)
 *     → main.c sandbox phases → jni_bridge.c (Android lifecycle)
 *
 * SESSION LIFECYCLE
 * =================
 *   1. Parse args, init platform, optionally harden the process.
 *   2. Open TCP connection (connect or listen for one peer).
 *   3. Handshake with 30-second timeout (2 rounds):
 *        a. Exchange version + commitment  (33 bytes each way)
 *        b. Exchange public keys           (32 bytes each way)
 *        c. Verify version, commitment, derive keys; abort on mismatch.
 *   4. Derive session keys (X25519 + transcript hash).
 *   5. Show safety code; wait for user to confirm out-of-band.
 *   6. Single-threaded event loop:
 *        - POSIX   : poll(socket, stdin)
 *        - Windows : WaitForMultipleObjects(console, winsock_event)
 *   7. Clean up: wipe all key material, close socket, restore console, exit.
 *
 * BUILDING
 * ========
 *   Linux / macOS:
 *     make    (or: gcc -O2 -std=c23 -Isrc -Ilib src/main.c ... -o simplecipher)
 *
 *   Windows (cross-compile):
 *     See CMakeLists.txt and CMakePresets.json for cmake presets.
 */

#include "protocol.h"
#include "network.h"
#include "tui.h"
#include "cli.h"
#if defined(_WIN32) || defined(_WIN64)
#    include <io.h> /* _read — bypass libc FILE* buffer for SAS input */
#endif

/* Exit codes — distinct values let scripts distinguish failure types. */
enum {
    EXIT_OK        = 0,
    EXIT_USAGE     = 1, /* bad arguments or --help */
    EXIT_NET       = 2, /* connection/listen failed */
    EXIT_HANDSHAKE = 3, /* handshake or commitment failed */
    EXIT_MITM      = 4, /* fingerprint mismatch or SAS mismatch */
    EXIT_SANDBOX   = 5, /* sandbox installation failed */
    EXIT_INTERNAL  = 6, /* platform init, key agreement, etc. */
    EXIT_ABORT     = 7, /* user aborted SAS verification (timeout, Ctrl+D, Ctrl+C) */
};

/* g_fd and g_sess are file-scope statics, passed as parameters to the
 * event loops.  They are static here so the cleanup code at the bottom
 * of main() can always reach them. */
static socket_t  g_fd = INVALID_SOCK;
static session_t g_sess;

/* ---- TUI listen resize callback ---------------------------------------- */

/* Context for the TUI listen screen idle callback, which redraws the
 * screen on terminal resize while waiting for a peer to connect. */
struct listen_ctx {
    const char *port;
    const char *ips;
};

static void tui_listen_idle(void *ctx) {
    struct listen_ctx *lc = (struct listen_ctx *)ctx;
    /* Check if terminal size changed; if so, redraw. */
    int w, h;
    tui_get_size(&w, &h);
    if (w != tui_w || h != tui_h) tui_listen_screen(lc->port, lc->ips);
}

/* ---- application -------------------------------------------------------- */

/* Print usage to stderr and exit. */
static void usage(const char *prog) {
    fprintf(stderr,
            "\n"
            "  SimpleCipher -- encrypted P2P chat\n"
            "\n"
            "  Usage:\n"
            "    %s listen  [port]          wait for a peer\n"
            "    %s connect [--socks5 proxy:port] [--peer-fingerprint XXXX-XXXX-XXXX-XXXX] <host> [port]\n"
            "                                connect to a peer\n"
            "\n"
            "  Options:\n"
            "    --tui                split-pane terminal interface\n"
            "    --socks5 host:port   connect through a SOCKS5 proxy (e.g. Tor)\n"
            "    --cover-traffic      hide when you type by sending constant\n"
            "                         encrypted noise (auto with --socks5;\n"
            "                         add manually when listening behind Tor)\n"
            "    --require-sandbox    abort if syscall sandbox fails to install\n"
            "    --peer-fingerprint   verify the peer's public key fingerprint\n"
            "    port                 default: 7777\n"
            "\n"
            "  After connecting, compare the safety code with your peer\n"
            "  over a separate channel (phone call, in person).\n"
#ifdef CIPHER_HARDEN
            "\n"
            "  Hardening (active in this build):\n"
            "    Memory locked, core dumps disabled, ptrace blocked.\n"
#endif
            "\n"
            "  Exit codes:\n"
            "    0  success      1  usage error    2  connection failed\n"
            "    3  handshake    4  MITM detected  5  sandbox failed\n"
            "    6  internal     7  SAS aborted\n"
            "\n",
            prog, prog);
    exit(EXIT_USAGE);
}

/* Program entry point.
 *
 * The core design is the same on both platforms: one thread, one session,
 * one TCP socket, one console.  The only difference is how each OS exposes
 * waitable input events. */
int main(int argc, char *argv[]) {
    int         we_init; /* 1 = connect (initiator), 0 = listen (responder) */
    const char *host = nullptr;
    const char *port = "7777";
    uint8_t     self_priv[KEY], self_pub[KEY], peer_pub[KEY];
    uint8_t     commit_self[KEY], commit_peer[KEY];
    uint8_t     sas_key[KEY];        /* SAS = Short Authentication String */
    char        sas[20];             /* formatted as "XXXX-XXXX" (32 bits, human-verifiable) */
    char        typed_sas[16] = {0}; /* user types the full SAS code to confirm */
    int         rc            = EXIT_INTERNAL;
    /* Windows console handle (h_in) and Winsock event (net_ev) are now
     * managed internally by cli_chat_loop() and tui_chat_loop(). */

    int         tui_mode         = 0;
    int         cover_traffic    = 0; /* explicit --cover-traffic or auto via --socks5 */
    const char *socks5_host      = nullptr;
    const char *socks5_port      = nullptr;
    const char *peer_fp_expected = nullptr;
    static char s5host[256];
    static char s5port[8];

    /* Parse all flags from argv in a single pass.  Flags can appear
     * anywhere — before or after the subcommand:
     *   simplecipher --tui connect --socks5 ... host
     *   simplecipher connect --peer-fingerprint ... host
     * We compact positional args (program, subcommand, host, port)
     * into the front of argv, stripping consumed flags. */
    const char *prog = argv[0];
    {
        int out = 1;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--tui") == 0) {
                tui_mode = 1;
            } else if (strcmp(argv[i], "--cover-traffic") == 0) {
                cover_traffic = 1;
            } else if (strcmp(argv[i], "--require-sandbox") == 0) {
                g_require_sandbox = 1;
            } else if (strcmp(argv[i], "--version") == 0) {
                printf("SimpleCipher v%d\n", PROTOCOL_VERSION);
                return 0;
            } else if (strcmp(argv[i], "--socks5") == 0 && i + 1 < argc) {
                const char *arg   = argv[++i];
                const char *colon = strrchr(arg, ':');
                if (!colon || colon == arg || !colon[1]) {
                    fprintf(stderr, "  --socks5 requires host:port format\n");
                    return EXIT_USAGE;
                }
                size_t hlen = (size_t)(colon - arg);
                if (hlen >= sizeof s5host) {
                    fprintf(stderr, "  socks5 host too long\n");
                    return EXIT_USAGE;
                }
                memcpy(s5host, arg, hlen);
                s5host[hlen] = '\0';
                snprintf(s5port, sizeof s5port, "%s", colon + 1);
                socks5_host = s5host;
                socks5_port = s5port;
                if (!validate_port(s5port)) {
                    fprintf(stderr, "  --socks5 port invalid: %s\n", s5port);
                    return EXIT_USAGE;
                }
            } else if (strcmp(argv[i], "--peer-fingerprint") == 0 && i + 1 < argc) {
                peer_fp_expected = argv[++i];
            } else {
                argv[out++] = argv[i];
            }
        }
        argc = out;
    }

    /* --socks5 implies --cover-traffic: if you're using Tor, you want
     * timing-correlation protection.  --cover-traffic can also be set
     * independently for listeners behind onion services or transparent
     * Tor routing (Whonix, Tails, Qubes sys-whonix). */
    if (socks5_host) cover_traffic = 1;

    if (argc < 2) usage(prog);
    harden(); /* First: lock memory, disable dumps, block ptrace — before
               * any key material exists.  Closes the pre-harden ptrace window. */
    if (plat_init() != 0) {
        fprintf(stderr, "platform init failed\n");
        return EXIT_INTERNAL;
    }

    /* Install signal handlers.
     *
     * We use sigaction() instead of signal() on POSIX because signal() has
     * implementation-defined reset behaviour: some systems restore SIG_DFL
     * after the first delivery, so a second Ctrl+C would kill the process
     * without cleanup.  sigaction() with SA_RESTART gives persistent,
     * well-defined behaviour on all POSIX platforms.
     *
     * SA_RESTART is intentionally NOT set: we want EINTR to interrupt
     * blocking syscalls (poll, accept) so the loop can recheck g_running.
     *
     * SIGHUP fires when the terminal window is closed (e.g. user closes
     * the terminal emulator, SSH connection drops).  Without this handler,
     * SIGHUP's default action is immediate process termination -- no cleanup,
     * no crypto_wipe, key material and chat plaintext linger in RAM until
     * the OS reclaims the pages.  Catching it lets us exit the event loop
     * cleanly and wipe all secrets.
     *
     * SIGQUIT (Ctrl+\) defaults to terminate + core dump.  A core dump is
     * a snapshot of the entire process address space written to disk --
     * including chain keys, message keys, and decrypted plaintext.  By
     * catching SIGQUIT the same way as SIGINT, we suppress the core dump
     * and run the cleanup path instead.  (CIPHER_HARDEN sets RLIMIT_CORE=0
     * as a belt-and-suspenders defence, but catching the signal is free.) */
#ifndef _WIN32
    {
        struct sigaction sa = {0};
        sa.sa_handler       = on_sig;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0; /* no SA_RESTART: let poll/accept return EINTR */
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGHUP, &sa, nullptr);  /* terminal closed / SSH dropped */
        sigaction(SIGQUIT, &sa, nullptr); /* Ctrl+\ -- suppress core dump with keys */
        sigaction(SIGALRM, &sa, nullptr); /* SAS verification timeout (alarm) */
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, nullptr); /* handle dropped peers via write errors */
    }
#else
    signal(SIGINT, on_sig);
    SetConsoleCtrlHandler(on_console_ctrl, TRUE); /* window close / logoff / shutdown */
#endif

    we_init = (strcmp(argv[1], "connect") == 0);
    if (!we_init && strcmp(argv[1], "listen") != 0) {
        fprintf(stderr, "  Unknown command: %s\n", argv[1]);
        usage(prog);
    }
    if (!we_init && socks5_host) {
        fprintf(stderr, "  Note: --socks5 has no effect in listen mode.\n");
        socks5_host = nullptr;
        socks5_port = nullptr;
    }

    /* Interactive connect prompt: if "connect" is given without a host,
     * prompt on stdin.  This keeps the target address out of argv, shell
     * history, and process listings — useful when connecting to sensitive
     * destinations (e.g. .onion addresses through --socks5). */
    static char prompt_host[256];
    static char prompt_port[8];

    if (we_init && argc < 3) {
        printf("  Host: ");
        fflush(stdout);
        /* read() instead of fgets() so the destination address never passes
         * through libc's internal ~4KB FILE* buffer (which is never wiped).
         * In canonical mode, read() returns a complete line from the kernel. */
        {
#if defined(_WIN32) || defined(_WIN64)
            int rn = _read(0, prompt_host, (unsigned)(sizeof prompt_host - 1));
#else
            ssize_t rn = read(STDIN_FILENO, prompt_host, sizeof prompt_host - 1);
#endif
            if (rn <= 0 || prompt_host[0] == '\n') {
                fprintf(stderr, "  No host provided.\n");
                return EXIT_USAGE;
            }
            prompt_host[rn] = '\0';
            /* Drain leftover bytes if input was truncated (no newline in buffer).
             * Without this, the tail spills into the port prompt. */
            {
                int had_newline = 0;
                for (int i = 0; i < rn; i++)
                    if (prompt_host[i] == '\n') {
                        had_newline = 1;
                        break;
                    }
                if (rn > 0 && prompt_host[rn - 1] == '\n') prompt_host[rn - 1] = '\0';
                if (!had_newline) {
                    char drain;
#if defined(_WIN32) || defined(_WIN64)
                    int dr;
                    do { dr = _read(0, &drain, 1); } while (dr == 1 && drain != '\n');
#else
                    ssize_t dr;
                    do { dr = read(STDIN_FILENO, &drain, 1); } while (dr == 1 && drain != '\n');
#endif
                }
            }
        }
        if (!prompt_host[0]) {
            fprintf(stderr, "  No host provided.\n");
            return EXIT_USAGE;
        }
        host = prompt_host;

        printf("  Port [7777]: ");
        fflush(stdout);
        {
#if defined(_WIN32) || defined(_WIN64)
            int rn = _read(0, prompt_port, (unsigned)(sizeof prompt_port - 1));
#else
            ssize_t rn = read(STDIN_FILENO, prompt_port, sizeof prompt_port - 1);
#endif
            if (rn > 0) {
                prompt_port[rn] = '\0';
                /* Drain oversized input */
                if (!memchr(prompt_port, '\n', (size_t)rn)) {
                    char drain;
#if defined(_WIN32) || defined(_WIN64)
                    int dr;
                    do { dr = _read(0, &drain, 1); } while (dr == 1 && drain != '\n');
#else
                    ssize_t dr;
                    do { dr = read(STDIN_FILENO, &drain, 1); } while (dr == 1 && drain != '\n');
#endif
                }
                if (rn > 0 && prompt_port[rn - 1] == '\n') prompt_port[rn - 1] = '\0';
                if (prompt_port[0]) port = prompt_port;
            }
        }
    } else if (we_init) {
        host = argv[2];
        if (!host[0]) {
            fprintf(stderr, "  Host cannot be empty.\n");
            rc = EXIT_USAGE;
            goto out;
        }
        if (argc >= 4) port = argv[3];
    } else {
        if (argc >= 3) port = argv[2];
    }
    if (!validate_port(port)) {
        fprintf(stderr, "invalid port: %s\n", port);
        rc = EXIT_USAGE;
        goto out;
    }

    /* NOTE: sandbox_phase1() is called AFTER the TCP connection is
     * established (see below), not here.  Connection setup requires
     * getifaddrs(), getaddrinfo(), socket(), connect(), bind(), listen(),
     * and accept() — syscalls that phase 1 intentionally blocks.
     * Installing the sandbox here would crash on hardened Linux/OpenBSD
     * builds.  Phase 1 goes right before the handshake, when untrusted
     * data first arrives over the wire. */

    if (tui_mode) tui_init_term();

    /* ------------------------------------------------------------------
     * STEP 0: Generate ephemeral keypair and compute fingerprint
     *
     * Done BEFORE the TCP connection so the listener can display and
     * share their fingerprint while waiting for a peer to connect.
     * The peer uses --peer-fingerprint to verify identity after the
     * handshake completes.
     *
     * The keypair is session-only: generated fresh every run, wiped at
     * exit.  Generating it a few seconds earlier (before listen/connect
     * instead of after) does not change the security properties — the
     * keys exist in RAM either way until the session ends.
     * ------------------------------------------------------------------ */

    gen_keypair(self_priv, self_pub);
    make_commit(commit_self, self_pub);

    char self_fp[20];
    format_fingerprint(self_fp, self_pub);

    if (!tui_mode) {
        printf("\n");
        printf("  SimpleCipher\n");
        printf("  No server. No account. Ephemeral keys.\n");
        printf("\n");
    }

    /* ------------------------------------------------------------------
     * STEP 1: TCP connection
     * ------------------------------------------------------------------ */

    if (we_init) {
        if (tui_mode) {
            char msg[80];
            snprintf(msg, sizeof msg, "Connecting to %s:%s ...", host, port);
            tui_status_screen(msg, "Ctrl+C to cancel");
            crypto_wipe(msg, sizeof msg); /* contains peer address */
        } else {
            printf("  Connecting to %s:%s ...", host, port);
            fflush(stdout);
        }
        if (socks5_host) {
            g_fd = connect_socket_socks5(socks5_host, socks5_port, host, port);
        } else {
            /* Refuse hostnames on direct connect — DNS resolution would
             * leak the destination to the local resolver (and network).
             * Only numeric IPs (digits+dots for IPv4, contains ':' for
             * IPv6) are safe.  Hostnames are fine through SOCKS5 because
             * the proxy resolves them, not us. */
            int numeric = 0;
            if (strchr(host, ':')) {
                numeric = 1; /* IPv6 */
            } else {
                numeric = 1;
                for (const char *p = host; *p; p++) {
                    if ((*p < '0' || *p > '9') && *p != '.') {
                        numeric = 0;
                        break;
                    }
                }
            }
            if (!numeric) {
                fprintf(stderr, "\n  Direct connect requires a numeric IP address, not a hostname.\n"
                                "  Hostnames cause DNS lookups that leak your destination.\n"
                                "  Use --socks5 for hostnames (e.g. .onion addresses).\n");
                rc = EXIT_USAGE;
                goto out;
            }
            g_fd = connect_socket_numeric(host, port);
        }
        if (g_fd == INVALID_SOCK) {
            fprintf(stderr,
                    "\n  Connection failed. Check the address and make sure\n"
                    "  the peer is listening on %s:%s.\n",
                    host, port);
            rc = EXIT_NET;
            goto out;
        }
        if (!tui_mode) printf(" ok\n");
    } else {
        if (tui_mode) {
            char ipbuf[1024];
            get_local_ips(ipbuf, sizeof ipbuf);
            tui_listen_screen(port, ipbuf);
            struct listen_ctx lc = {port, ipbuf};
            g_fd                 = listen_socket_cb(port, tui_listen_idle, &lc);
            crypto_wipe(ipbuf, sizeof ipbuf); /* wipe local IP addresses */
        } else {
            printf("  Listening on port %s\n\n", port);
            printf("  Tell your peer to run:\n\n");
            print_local_ips(port);
            printf("\n");
            printf("  Your fingerprint: %s\n", self_fp);
            printf("  (share with peer for --peer-fingerprint verification)\n\n");
            printf("  Waiting for connection... (Ctrl+C to cancel)");
            fflush(stdout);
            g_fd = listen_socket(port);
        }
        if (g_fd == INVALID_SOCK) {
            if (tui_mode) tui_status_screen("Listen failed", "");
            else fprintf(stderr, "\n  Listen failed. Is port %s already in use?\n", port);
            rc = EXIT_NET;
            goto out;
        }
        if (tui_mode) tui_status_screen("Peer connected", "Performing handshake...");
        else printf(" ok\n");
    }

    /* On Windows, register the connected socket so Ctrl+C can close it
     * from the console handler thread, unblocking any recv/send during
     * the handshake.  Cleared when we enter the event loop (which has
     * its own non-blocking I/O strategy). */
#if defined(_WIN32) || defined(_WIN64)
    g_interrupt_sock = g_fd;
#endif

    /* Phase 1 sandbox: restrict syscalls to those needed for the handshake.
     * Blocks socket(), connect(), bind(), listen(), accept(), and DNS.
     * A compromised process can no longer open new connections.
     *   Linux:   seccomp-BPF filter (kernel kills process on violation)
     *   FreeBSD: Capsicum cap_enter() + per-fd capability rights
     *   OpenBSD: pledge("stdio") + unveil(NULL, NULL)
     *   Windows: no equivalent (no sandbox on this platform)
     * Skip this on first reading — the protocol works without it. */
    /* Set socket timeouts BEFORE the sandbox — setsockopt is blocked by
     * OpenBSD pledge("stdio") and FreeBSD Capsicum phase 2.  The handshake
     * uses deadline-aware I/O (15s per exchange round) on top of this
     * backstop.  The chat phase reuses the same SO_RCVTIMEO/SO_SNDTIMEO. */
    set_sock_timeout(g_fd, FRAME_TIMEOUT_S);

    if (sandbox_phase1((int)g_fd) != 0) {
        fprintf(stderr, "sandbox installation failed (--require-sandbox)\n");
        rc = EXIT_SANDBOX;
        goto out;
    }

    /* ------------------------------------------------------------------
     * STEP 2: Commit-then-reveal handshake
     *
     * Both sides commit to their keys before revealing them.
     * This prevents an attacker from adaptively brute-forcing the SAS
     * after seeing one side's key (see make_commit in crypto.h for the
     * full argument).
     *
     * gen_keypair + make_commit were already called in STEP 0 (before
     * listen/connect) so the fingerprint could be shown on the listen
     * screen for pre-sharing.
     * ------------------------------------------------------------------ */

    /* Two-round handshake (v3):
     *   Round 1: version || commitment  (33 bytes each way)
     *   Round 2: public key             (32 bytes each way)
     *
     * Both rounds always complete before any verification.  This makes
     * version-mismatch and commitment-mismatch failures indistinguishable
     * from the wire (same number of bytes exchanged, same timing pattern),
     * preventing a network observer from fingerprinting the failure mode.
     *
     * The commitment scheme is preserved: both sides commit (round 1)
     * before either reveals (round 2). */
    {
        uint8_t out1[1 + KEY], in1[1 + KEY];
        out1[0] = (uint8_t)PROTOCOL_VERSION;
        memcpy(out1 + 1, commit_self, KEY);
        if (exchange(g_fd, we_init, out1, sizeof out1, in1, sizeof in1) != 0) {
            fprintf(stderr, "handshake error (round 1: version + commitment)\n");
            crypto_wipe(out1, sizeof out1);
            crypto_wipe(in1, sizeof in1);
            rc = EXIT_HANDSHAKE;
            goto out;
        }
        uint8_t peer_ver = in1[0];
        memcpy(commit_peer, in1 + 1, KEY);
        crypto_wipe(out1, sizeof out1);
        crypto_wipe(in1, sizeof in1);

        if (exchange(g_fd, we_init, self_pub, KEY, peer_pub, KEY) != 0) {
            fprintf(stderr, "handshake error (round 2: keys)\n");
            rc = EXIT_HANDSHAKE;
            goto out;
        }

        if (peer_ver != PROTOCOL_VERSION) {
            fprintf(stderr, "version mismatch: we are v%d, peer is v%d\n", PROTOCOL_VERSION, (int)peer_ver);
            rc = EXIT_HANDSHAKE;
            goto out;
        }
    }

    /* SO_RCVTIMEO/SO_SNDTIMEO was already set to FRAME_TIMEOUT_S before
     * sandbox_phase1.  No need to re-arm — the handshake uses deadline
     * I/O, and the chat phase reuses the same socket timeout as a backstop.
     * Cannot call setsockopt here: blocked by pledge/Capsicum/seccomp. */

    if (!verify_commit(commit_peer, peer_pub)) {
        fprintf(stderr, "[!] commitment mismatch -- possible MITM attack\n");
        rc = EXIT_MITM;
        goto out;
    }
    crypto_wipe(commit_self, sizeof commit_self);
    crypto_wipe(commit_peer, sizeof commit_peer);

    /* ------------------------------------------------------------------
     * STEP 3: Session key derivation
     * ------------------------------------------------------------------ */

    if (session_init(&g_sess, we_init, self_priv, self_pub, peer_pub, sas_key) != 0) {
        fprintf(stderr, "key agreement failed (bad peer key)\n");
        rc = EXIT_HANDSHAKE;
        goto out;
    }
    crypto_wipe(self_priv, sizeof self_priv); /* private key no longer needed */

    /* Fingerprint verification: an optional second layer of identity assurance.
     *
     * The listener's fingerprint was already shown on the listen screen
     * (STEP 0/1) so it can be pre-shared before the peer connects.
     *
     * In connect mode with --peer-fingerprint, verify the peer's key matches
     * the expected fingerprint.  This catches MITM attacks even before the
     * SAS comparison, and does not require an interactive voice call. */
    {
        char peer_fp[20];
        format_fingerprint(peer_fp, peer_pub);

        if (peer_fp_expected) {
            /* Strip dashes and uppercase both strings before comparing. */
            char ne[20] = {0}, np[20] = {0};
            int  ei = 0, pi = 0;
            for (int i = 0; peer_fp_expected[i] && ei < (int)sizeof(ne) - 1; i++) {
                char c = peer_fp_expected[i];
                if (c == '-') continue;
                if (c >= 'a' && c <= 'z') c -= 32;
                ne[ei++] = c;
            }
            for (int i = 0; peer_fp[i] && pi < (int)sizeof(np) - 1; i++) {
                char c = peer_fp[i];
                if (c == '-') continue;
                if (c >= 'a' && c <= 'z') c -= 32;
                np[pi++] = c;
            }
            int mismatch = (ei != pi) || ct_compare((const uint8_t *)ne, (const uint8_t *)np, (size_t)ei) != 0;
            crypto_wipe(ne, sizeof ne);
            crypto_wipe(np, sizeof np);
            if (mismatch) {
                if (tui_mode) tui_restore_term(); /* exit alternate screen so error is visible */
                fprintf(stderr,
                        "\n  [!] Peer fingerprint mismatch!\n"
                        "  Expected: %s\n"
                        "  Got:      %s\n"
                        "  Aborting -- possible MITM attack.\n",
                        peer_fp_expected, peer_fp);
                crypto_wipe(peer_fp, sizeof peer_fp);
                rc = EXIT_MITM;
                goto out;
            }
            if (!tui_mode) printf("  Peer fingerprint verified: %s\n", peer_fp);
        }
        crypto_wipe(peer_fp, sizeof peer_fp);
    }
    crypto_wipe(self_fp, sizeof self_fp);

    /* ------------------------------------------------------------------
     * STEP 4: Out-of-band safety code verification
     *
     * Both sides display the same code derived from the shared secret.
     * Call the peer on a separate channel and compare it aloud.
     * If it does not match, an attacker is relaying the connection.
     * ------------------------------------------------------------------ */

    format_sas(sas, sas_key);

#if defined(_WIN32) || defined(_WIN64)
    g_interrupt_sock = INVALID_SOCKET; /* event loops handle their own I/O */
#endif

    if (tui_mode) {
        /* tui_init_term() was already called before TCP connection */
        int sas_ok = tui_sas_screen(sas, g_fd);
        crypto_wipe(sas_key, sizeof sas_key);
        crypto_wipe(sas, sizeof sas);
        if (sas_ok <= 0) {
            tui_restore_term(); /* exit alternate screen NOW so error is visible */
            if (sas_ok < 0) {
                fprintf(stderr, "Code mismatch -- aborted.\n");
                rc = EXIT_MITM;
            } else {
                fprintf(stderr, "Aborted.\n");
                rc = EXIT_ABORT;
            }
            goto out;
        }

        if (sandbox_phase2((int)g_fd) != 0) { /* tighten: drop setsockopt (Capsicum), setup syscalls (seccomp) */
            fprintf(stderr, "sandbox phase 2 failed (--require-sandbox)\n");
            rc = EXIT_SANDBOX;
            goto out;
        }
        tui_chat_loop(g_fd, &g_sess, cover_traffic);
    } else {
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
                (void)write(STDOUT_FILENO, sas_line, (size_t)sn);
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
            WSAEventSelect(g_fd, sas_ev, FD_CLOSE);
            {
                HANDLE sas_waits[2] = {h_stdin, sas_ev};
                while (g_running) {
                    uint64_t now_w = GetTickCount64();
                    if (now_w >= sas_dl_win) {
                        printf("SAS verification timed out.\n");
                        rc = EXIT_ABORT;
                        WSAEventSelect(g_fd, sas_ev, 0);
                        WSACloseEvent(sas_ev);
                        goto out;
                    }
                    DWORD wr = WaitForMultipleObjects(2, sas_waits, FALSE, 1000);
                    if (wr == WAIT_OBJECT_0 + 1) {
                        fprintf(stderr, "Peer disconnected during SAS verification.\n");
                        rc = EXIT_NET;
                        WSAEventSelect(g_fd, sas_ev, 0);
                        WSACloseEvent(sas_ev);
                        goto out;
                    }
                    if (wr == WAIT_OBJECT_0) {
                        rn = _read(0, typed_sas, (unsigned)(sizeof typed_sas - 1));
                        break;
                    }
                    /* WAIT_TIMEOUT: loop back, recheck g_running + deadline */
                }
            }
            WSAEventSelect(g_fd, sas_ev, 0);
            WSACloseEvent(sas_ev);
            if (!g_running) {
                printf("Aborted.\n");
                rc = EXIT_ABORT;
                goto out;
            }
#else
            ssize_t rn = -1;
            {
                struct pollfd sas_fds[2]   = {{STDIN_FILENO, POLLIN, 0}, {g_fd, 0, 0}};
                uint64_t      sas_deadline = monotonic_ms() + 300000; /* 5-minute timeout */
                while (g_running) {
                    int64_t remain = (int64_t)(sas_deadline - monotonic_ms());
                    if (remain <= 0) {
                        printf("SAS verification timed out.\n");
                        rc = EXIT_ABORT;
                        goto out;
                    }
                    int poll_ms = remain > 1000 ? 1000 : (int)remain;
                    int pr      = poll(sas_fds, 2, poll_ms);
                    if (pr < 0 && errno == EINTR) continue;
                    if (pr < 0) break;
                    if (sas_fds[1].revents & (POLLHUP | POLLERR)) {
                        fprintf(stderr, "Peer disconnected during SAS verification.\n");
                        rc = EXIT_NET;
                        goto out;
                    }
                    if (sas_fds[0].revents & POLLIN) {
                        rn = read(STDIN_FILENO, typed_sas, sizeof typed_sas - 1);
                        break;
                    }
                }
                if (!g_running) { /* Ctrl+C or signal */
                    printf("Aborted.\n");
                    rc = EXIT_ABORT;
                    goto out;
                }
            }
#endif
            if (rn <= 0) {
                printf("Aborted.\n");
                rc = EXIT_ABORT;
                goto out;
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
            int  ti = 0, si = 0;
            for (int i = 0; typed_sas[i] && ti < (int)sizeof(nt) - 1; i++) {
                char c = typed_sas[i];
                if (c == '-') continue;
                if (c >= 'a' && c <= 'z') c -= 32;
                nt[ti++] = c;
            }
            for (int i = 0; sas[i] && si < (int)sizeof(ns) - 1; i++) {
                char c = sas[i];
                if (c == '-') continue;
                if (c >= 'a' && c <= 'z') c -= 32;
                ns[si++] = c;
            }
            int mismatch = (ti != si || ct_compare((const uint8_t *)nt, (const uint8_t *)ns, (size_t)ti) != 0);
            crypto_wipe(nt, sizeof nt);
            crypto_wipe(ns, sizeof ns);
            if (mismatch) {
                printf("\n  Code mismatch -- aborted.\n");
                rc = EXIT_MITM;
                goto out;
            }
        }
        crypto_wipe(sas_key, sizeof sas_key);
        crypto_wipe(sas, sizeof sas);

        /* ------------------------------------------------------------------
     * STEP 5: event loop
     *
     * Single-threaded on both platforms.
     *   - POSIX   waits on socket + stdin with poll()
     *   - Windows waits on console input + Winsock event with
     *     WaitForMultipleObjects()
     *
     * On peer disconnect or auth failure, we print a notice and break.
     * On Ctrl+C, g_running is cleared and the loop exits on the next
     * 250 ms WaitForMultipleObjects timeout.
     * ------------------------------------------------------------------ */

        printf("\n");
        printf("  Secure session active. Ctrl+C to quit.\n");
        printf("  Type a message and press Enter to send.\n");
        printf("\n");

        if (sandbox_phase2((int)g_fd) != 0) { /* tighten: drop setsockopt (Capsicum), setup syscalls (seccomp) */
            fprintf(stderr, "sandbox phase 2 failed (--require-sandbox)\n");
            rc = EXIT_SANDBOX;
            goto out;
        }
        cli_chat_loop(g_fd, &g_sess, cover_traffic);
    } /* end else (CLI mode) */

    sock_shutdown_both(g_fd);
    close_sock(g_fd);
    g_fd = INVALID_SOCK;
    /* EXIT_OK only if the user chose to quit (Ctrl+C set g_running=0).
     * If the loop broke for another reason (peer disconnect, auth failure,
     * send error), g_running is still 1 — report as network error. */
    rc        = g_running ? EXIT_NET : EXIT_OK;
    g_running = 0;

out:
    /* Always reached.  Wiping uninitialised or already-zero variables is safe. */
    if (g_fd != INVALID_SOCK) {
        sock_shutdown_both(g_fd);
        close_sock(g_fd);
    }
    session_wipe(&g_sess);
    crypto_wipe(self_priv, sizeof self_priv);
    crypto_wipe(self_pub, sizeof self_pub);
    crypto_wipe(peer_pub, sizeof peer_pub);
    crypto_wipe(commit_self, sizeof commit_self);
    crypto_wipe(commit_peer, sizeof commit_peer);
    crypto_wipe(sas_key, sizeof sas_key);
    crypto_wipe(sas, sizeof sas);
    crypto_wipe(typed_sas, sizeof typed_sas);
    crypto_wipe(prompt_host, sizeof prompt_host);
    crypto_wipe(prompt_port, sizeof prompt_port);
    crypto_wipe(s5host, sizeof s5host);
    crypto_wipe(s5port, sizeof s5port);
    /* Clear the terminal screen and scrollback buffer so messages don't
     * linger in terminal history.  TUI mode uses an alternate screen buffer
     * (\033[?1049h/l) which is restored automatically on exit — purging there
     * would clear the user's previous scrollback, so we skip it. */
    if (!tui_mode) purge_terminal();

    /* Tell the user the session is gone.  This is the last thing they see.
     * Factual, not overstated: keys are wiped, nothing was written to disk,
     * but OS-level traces (swap, scrollback) are outside our control. */
    if (rc == EXIT_OK) printf("\n  Session ended. Keys wiped. Nothing was stored to disk.\n\n");

    plat_quit();
    return rc;
}
