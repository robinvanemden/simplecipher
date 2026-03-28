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
 *   1. main.c        (this file)   — session lifecycle orchestration
 *   2. args.h        — CLI config struct, exit codes, parse_args()
 *   3. verify.h      — identity verification (passphrase, fingerprint, SAS)
 *   4. protocol.h    — wire format, frame layout, session key derivation
 *   5. crypto.h      — cryptographic building blocks (KDF, ratchet, SAS)
 *   6. ratchet.h     — DH ratchet for post-compromise security
 *   7. network.h     — TCP socket I/O
 *   8. tui.h / cli.h — user interface event loops
 *   9. platform.h    — OS abstraction (sockets, RNG, signals)
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

#include "args.h"
#include "verify.h"
#include "protocol.h"
#include "network.h"
#include "tui.h"
#include "cli.h"

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

/* ---- helpers ------------------------------------------------------------ */

/* Enter phase-2 sandbox and start the chat event loop.
 * Returns 0 on success, EXIT_SANDBOX on sandbox failure. */
static int start_chat_phase(socket_t fd, session_t *sess, int cover, int tui) {
    if (sandbox_phase2((int)fd) != 0) {
        fprintf(stderr, "sandbox phase 2 failed (--require-sandbox)\n");
        return EXIT_SANDBOX;
    }
    if (tui) {
        tui_chat_loop(fd, sess, cover);
    } else {
        printf("\n");
        cli_chat_loop(fd, sess, cover);
    }
    return 0;
}

/* Program entry point.
 *
 * The core design is the same on both platforms: one thread, one session,
 * one TCP socket, one console.  The only difference is how each OS exposes
 * waitable input events. */
int main(int argc, char *argv[]) {
    uint8_t self_priv[KEY], self_pub[KEY], peer_pub[KEY];
    uint8_t commit_self[KEY], commit_peer[KEY];
    uint8_t sas_key[KEY]; /* SAS = Short Authentication String */
    char    sas[20];      /* formatted as "XXXX-XXXX" (32 bits, human-verifiable) */
    int     rc = EXIT_INTERNAL;

    config_t cfg = parse_args(argc, argv);

    harden(); /* First: lock memory, disable dumps, block ptrace — before
               * any key material exists.  Closes the pre-harden ptrace window. */
    if (plat_init() != 0) {
        fprintf(stderr, "platform init failed\n");
        return EXIT_INTERNAL;
    }

    /* keygen subcommand — generate a persistent identity key file.
     * Runs before signal handlers because it exits immediately. */
    if (cfg.is_keygen) return keygen_main(cfg.keygen_path);

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
        sigaction(SIGALRM, &sa, nullptr); /* clean shutdown on stray SIGALRM */
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, nullptr); /* handle dropped peers via write errors */
    }
#else
    signal(SIGINT, on_sig);
    SetConsoleCtrlHandler(on_console_ctrl, TRUE); /* window close / logoff / shutdown */
#endif

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

    if (!cfg.tui_mode) {
        printf("\n");
        printf("  SimpleCipher\n");
        printf("  No server. No account. Ephemeral keys.\n");
        printf("\n");
    }

    /* --identity: load a persistent identity key instead of the ephemeral
     * one just generated.  The persistent key gives a stable fingerprint
     * across sessions, enabling the paper fingerprint workflow. */
    if (cfg.identity_path) {
        char pass[256];
        int  plen = read_passphrase("  Enter passphrase: ", pass, sizeof pass);
        if (plen <= 0) {
            crypto_wipe(pass, sizeof pass);
            fprintf(stderr, "  Empty passphrase.\n");
            return EXIT_USAGE;
        }
        if (identity_load(cfg.identity_path, self_priv, self_pub, pass, (size_t)plen) != 0) {
            crypto_wipe(pass, sizeof pass);
            fprintf(stderr, "  Failed to decrypt %s — wrong passphrase or corrupt file.\n", cfg.identity_path);
            return EXIT_MITM;
        }
        crypto_wipe(pass, sizeof pass);
        /* Recompute commitment and fingerprint with the persistent key */
        make_commit(commit_self, self_pub);
        format_fingerprint(self_fp, self_pub);
    }

    if (cfg.tui_mode) tui_init_term();

    /* ------------------------------------------------------------------
     * STEP 1: TCP connection
     * ------------------------------------------------------------------ */

    if (cfg.we_init) {
        if (cfg.tui_mode) {
            char msg[80];
            snprintf(msg, sizeof msg, "Connecting to %s:%s ...", cfg.host, cfg.port);
            tui_status_screen(msg, "Ctrl+C to cancel");
            crypto_wipe(msg, sizeof msg); /* contains peer address */
        } else {
            printf("  Connecting to %s:%s ...", cfg.host, cfg.port);
            fflush(stdout);
        }
        if (cfg.socks5_host) {
            g_fd = connect_socket_socks5(cfg.socks5_host, cfg.socks5_port, cfg.host, cfg.port);
        } else {
            /* Refuse hostnames on direct connect — DNS resolution would
             * leak the destination to the local resolver (and network).
             * Only numeric IPs (digits+dots for IPv4, contains ':' for
             * IPv6) are safe.  Hostnames are fine through SOCKS5 because
             * the proxy resolves them, not us. */
            int numeric = 0;
            if (strchr(cfg.host, ':')) {
                numeric = 1; /* IPv6 */
            } else {
                numeric = 1;
                for (const char *p = cfg.host; *p; p++) {
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
            g_fd = connect_socket_numeric(cfg.host, cfg.port);
        }
        if (g_fd == INVALID_SOCK) {
            fprintf(stderr,
                    "\n  Connection failed. Check the address and make sure\n"
                    "  the peer is listening on %s:%s.\n",
                    cfg.host, cfg.port);
            rc = EXIT_NET;
            goto out;
        }
        if (!cfg.tui_mode) printf(" ok\n");
    } else {
        if (cfg.tui_mode) {
            char ipbuf[1024];
            get_local_ips(ipbuf, sizeof ipbuf);
            tui_listen_screen(cfg.port, ipbuf);
            struct listen_ctx lc = {cfg.port, ipbuf};
            g_fd                 = listen_socket_cb(cfg.port, tui_listen_idle, &lc);
            crypto_wipe(ipbuf, sizeof ipbuf); /* wipe local IP addresses */
        } else {
            printf("  Listening on port %s\n\n", cfg.port);
            printf("  Tell your peer to run:\n\n");
            print_local_ips(cfg.port);
            printf("\n");
            printf("  Your fingerprint: %s\n", self_fp);
            printf("  (share with peer for --peer-fingerprint verification)\n\n");
            printf("  Waiting for connection... (Ctrl+C to cancel)");
            fflush(stdout);
            g_fd = listen_socket(cfg.port);
        }
        if (g_fd == INVALID_SOCK) {
            if (cfg.tui_mode) tui_status_screen("Listen failed", "");
            else fprintf(stderr, "\n  Listen failed. Is port %s already in use?\n", cfg.port);
            rc = EXIT_NET;
            goto out;
        }
        if (cfg.tui_mode) tui_status_screen("Peer connected", "Performing handshake...");
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

    /* Two-round handshake:
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
        if (exchange(g_fd, cfg.we_init, out1, sizeof out1, in1, sizeof in1) != 0) {
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

        if (exchange(g_fd, cfg.we_init, self_pub, KEY, peer_pub, KEY) != 0) {
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

    if (session_init(&g_sess, cfg.we_init, self_priv, self_pub, peer_pub, sas_key) != 0) {
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
    if (verify_peer_fingerprint(peer_pub, cfg.peer_fp_expected, cfg.tui_mode) != 0) {
        rc = EXIT_MITM;
        goto out;
    }
    crypto_wipe(self_fp, sizeof self_fp);

    /* ------------------------------------------------------------------
     * STEP 4: Out-of-band safety code verification
     *
     * Both sides display the same code derived from the shared secret.
     * Call the peer on a separate channel and compare it aloud.
     * If it does not match, an attacker is relaying the connection.
     *
     * --trust-fingerprint: when the peer fingerprint was verified above,
     * the 64-bit fingerprint (stronger than 32-bit SAS) is treated as
     * sufficient.  Skip the interactive SAS screen entirely and proceed
     * to the chat phase.  The commitment scheme prevents brute-forcing
     * a matching fingerprint, so this is cryptographically sound. */

    format_sas(sas, sas_key);

#if defined(_WIN32) || defined(_WIN64)
    g_interrupt_sock = INVALID_SOCKET; /* event loops handle their own I/O */
#endif

    if (cfg.trust_fingerprint) {
        /* Fingerprint already verified in STEP 3 — skip SAS. */
        if (!cfg.tui_mode) printf("  Fingerprint verified — SAS confirmation skipped.\n");
        crypto_wipe(sas_key, sizeof sas_key);
        crypto_wipe(sas, sizeof sas);

        rc = start_chat_phase(g_fd, &g_sess, cfg.cover_traffic, cfg.tui_mode);
        if (rc != 0) goto out;
        rc = 0;
        goto out;
    }

    if (cfg.tui_mode) {
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

        rc = start_chat_phase(g_fd, &g_sess, cfg.cover_traffic, 1);
        if (rc != 0) goto out;
    } else {
        rc = cli_sas_verify(sas, g_fd);
        crypto_wipe(sas_key, sizeof sas_key);
        crypto_wipe(sas, sizeof sas);
        if (rc != EXIT_OK) goto out;

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

        rc = start_chat_phase(g_fd, &g_sess, cfg.cover_traffic, 0);
        if (rc != 0) goto out;
    }

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
    args_wipe(); /* wipe host addresses and port buffers */
    /* Clear the terminal screen and scrollback buffer so messages don't
     * linger in terminal history.  TUI mode uses an alternate screen buffer
     * (\033[?1049h/l) which is restored automatically on exit — purging there
     * would clear the user's previous scrollback, so we skip it. */
    if (!cfg.tui_mode) purge_terminal();

    /* Tell the user the session is gone.  This is the last thing they see.
     * Factual, not overstated: keys are wiped, nothing was written to disk,
     * but OS-level traces (swap, scrollback) are outside our control. */
    if (rc == EXIT_OK) printf("\n  Session ended. Keys wiped. Nothing was stored to disk.\n\n");

    plat_quit();
    return rc;
}
