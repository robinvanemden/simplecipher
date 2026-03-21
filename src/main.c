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
 *   4. network.h     — TCP socket I/O
 *   5. tui.h / cli.h — user interface event loops
 *   6. platform.h    — OS abstraction (sockets, RNG, signals)
 *
 * SESSION LIFECYCLE
 * =================
 *   1. Parse args, init platform, optionally harden the process.
 *   2. Open TCP connection (connect or listen for one peer).
 *   3. Handshake with 30-second timeout:
 *        a. Exchange version bytes
 *        b. Exchange commitments  H(our_key) <-> H(peer_key)
 *        c. Exchange public keys  our_key    <-> peer_key
 *        d. Verify commitment matches reveal; abort if not.
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

/* g_fd and g_sess are file-scope statics, passed as parameters to the
 * event loops.  They are static here so the cleanup code at the bottom
 * of main() can always reach them. */
static socket_t  g_fd   = INVALID_SOCK;
static session_t g_sess;

/* ---- application -------------------------------------------------------- */

/* Print usage to stderr and exit. */
static void usage(const char *prog){
    fprintf(stderr,
        "cipher -- small authenticated P2P encrypted chat\n\n"
        "usage:\n"
        "  %s [--tui] listen  [port]\n"
        "  %s [--tui] connect <host> [port]\n\n"
        "default port: 7777\n\n"
        "authentication:\n"
        "  after connecting, both sides see the same safety code.\n"
        "  compare it out of band (phone call) before typing anything.\n\n"
        "anonymity:\n"
        "  for anonymity, run over Tor: torsocks %s connect ...\n"
#ifdef CIPHER_HARDEN
        "\nhardening (active):\n"
        "  this build locks memory, disables core dumps, and blocks ptrace.\n"
        "  if mlockall warns, run: ulimit -l unlimited\n"
#endif
        , prog, prog, prog);
    exit(1);
}

/* Program entry point.
 *
 * The core design is the same on both platforms: one thread, one session,
 * one TCP socket, one console.  The only difference is how each OS exposes
 * waitable input events. */
int main(int argc, char *argv[]){
    int          we_init;
    const char  *host = nullptr;
    const char  *port = "7777";
    uint8_t      self_priv[KEY], self_pub[KEY], peer_pub[KEY];
    uint8_t      commit_self[KEY], commit_peer[KEY];
    uint8_t      sas_key[KEY];
    char         sas[20];
    char         typed_sas[8] = {0};  /* user types first 4 chars of SAS to confirm */
    int          rc = 1;
    /* Windows console handle (h_in) and Winsock event (net_ev) are now
     * managed internally by cli_chat_loop() and tui_chat_loop(). */

    int tui_mode = 0;

    /* Check for --tui flag and shift argv */
    if (argc >= 2 && strcmp(argv[1], "--tui") == 0){
        tui_mode = 1;
        argv++;
        argc--;
    }

    if (argc < 2) usage(argv[0]);
    if (plat_init() != 0){ fprintf(stderr, "platform init failed\n"); return 1; }
    harden();

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
        sa.sa_handler = on_sig;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;  /* no SA_RESTART: let poll/accept return EINTR */
        sigaction(SIGINT,  &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGHUP,  &sa, nullptr);  /* terminal closed / SSH dropped */
        sigaction(SIGQUIT, &sa, nullptr);  /* Ctrl+\ -- suppress core dump with keys */
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, nullptr);  /* handle dropped peers via write errors */
    }
#else
    signal(SIGINT, on_sig);
    SetConsoleCtrlHandler(on_console_ctrl, TRUE);  /* window close / logoff / shutdown */
#endif

    we_init = (strcmp(argv[1], "connect") == 0);
    if (!we_init && strcmp(argv[1], "listen") != 0) usage(argv[0]);
    if (we_init && argc < 3) usage(argv[0]);
    if (we_init){ host = argv[2]; if (argc >= 4) port = argv[3]; }
    else        {                  if (argc >= 3) port = argv[2]; }
    if (!validate_port(port)){ fprintf(stderr, "invalid port: %s\n", port); return 1; }

    if (tui_mode) tui_init_term();

    if (!tui_mode)
        printf("cipher  |  no server, no account, x25519 + SAS\n\n");

    /* ------------------------------------------------------------------
     * STEP 1: TCP connection
     * ------------------------------------------------------------------ */

    if (we_init){
        if (tui_mode){
            char msg[80]; snprintf(msg, sizeof msg, "Connecting to %s:%s ...", host, port);
            tui_status_screen(msg, nullptr);
        } else {
            printf("Connecting to %s:%s ...\n", host, port); fflush(stdout);
        }
        g_fd = connect_socket(host, port);
        if (g_fd == INVALID_SOCK){ fprintf(stderr, "connect failed\n"); goto out; }
        if (!tui_mode) printf("Connected.\n");
    } else {
        if (tui_mode){
            char msg[80]; snprintf(msg, sizeof msg, "Waiting on port %s", port);
            tui_status_screen(msg, "Tell your peer to connect");
        } else {
            printf("Waiting on port %s — tell your peer to run:\n\n", port);
            print_local_ips(port);
            printf("\n"); fflush(stdout);
        }
        g_fd = listen_socket(port);
        if (g_fd == INVALID_SOCK){ fprintf(stderr, "listen/accept failed\n"); goto out; }
        if (tui_mode) tui_status_screen("Peer connected", "Performing handshake...");
        else printf("Peer connected.\n");
    }

    /* ------------------------------------------------------------------
     * STEP 2: Commit-then-reveal handshake
     *
     * Both sides commit to their keys before revealing them.
     * This prevents an attacker from adaptively brute-forcing the SAS
     * after seeing one side's key (see make_commit in crypto.h for the
     * full argument).
     * ------------------------------------------------------------------ */

    gen_keypair(self_priv, self_pub);
    make_commit(commit_self, self_pub);

    /* 30-second timeout: disconnect a peer who stalls during the handshake.
     * Removed after the handshake so idle chat sessions are not affected. */
    set_sock_timeout(g_fd, HANDSHAKE_TIMEOUT_S);

    /* Version exchange: send and receive a single version byte before any
     * cryptographic material.  If the versions differ, both sides get a
     * clear "version mismatch" error rather than a cryptic commitment
     * failure.  Increment PROTOCOL_VERSION whenever the frame layout or
     * KDF labels change. */
    {
        uint8_t my_ver  = (uint8_t)PROTOCOL_VERSION;
        uint8_t peer_ver = 0;
        if (exchange(g_fd, we_init, &my_ver, 1, &peer_ver, 1) != 0){
            fprintf(stderr, "handshake error (version exchange)\n"); goto out; }
        if (peer_ver != PROTOCOL_VERSION){
            fprintf(stderr, "version mismatch: we are v%d, peer is v%d\n",
                    PROTOCOL_VERSION, (int)peer_ver);
            goto out;
        }
    }

    if (exchange(g_fd, we_init, commit_self, KEY, commit_peer, KEY) != 0){
        fprintf(stderr, "handshake error (round 1: commitments)\n"); goto out; }
    if (exchange(g_fd, we_init, self_pub,    KEY, peer_pub,    KEY) != 0){
        fprintf(stderr, "handshake error (round 2: keys)\n"); goto out; }

    set_sock_timeout(g_fd, 0);  /* I/O phase of handshake done; verify_commit
                                 * below is pure computation, needs no timeout */

#ifndef _WIN32
    /* POSIX chat-phase read timeout.
     *
     * poll() returns only when data has actually started arriving, so this
     * timeout does NOT fire on idle silence between messages -- two people
     * can sit quietly for hours without being disconnected.
     *
     * What it DOES prevent: a peer who connects, completes the handshake,
     * then sends the first few bytes of a frame and stalls.  poll() would
     * return (data arrived), but read_exact would then block forever waiting
     * for the remaining bytes.  With a 30-second SO_RCVTIMEO, read_exact
     * returns -1 if the full frame does not arrive within 30 seconds of
     * poll() waking up.  Any real network delivers 512 bytes in milliseconds
     * once transmission has started.
     *
     * Windows uses a different strategy: WSAEventSelect puts the socket in
     * non-blocking mode, so partial frames are accumulated in a small buffer
     * and never block the event loop. */
    set_sock_timeout(g_fd, FRAME_TIMEOUT_S);
#endif

    if (!verify_commit(commit_peer, peer_pub)){
        fprintf(stderr, "[!] commitment mismatch -- possible MITM attack\n");
        goto out;
    }
    crypto_wipe(commit_self, sizeof commit_self);
    crypto_wipe(commit_peer, sizeof commit_peer);

    /* ------------------------------------------------------------------
     * STEP 3: Session key derivation
     * ------------------------------------------------------------------ */

    if (session_init(&g_sess, we_init,
                     self_priv, self_pub, peer_pub,
                     sas_key) != 0){
        fprintf(stderr, "key agreement failed (bad peer key)\n"); goto out;
    }
    crypto_wipe(self_priv, sizeof self_priv);  /* private key no longer needed */

    /* ------------------------------------------------------------------
     * STEP 4: Out-of-band safety code verification
     *
     * Both sides display the same code derived from the shared secret.
     * Call the peer on a separate channel and compare it aloud.
     * If it does not match, an attacker is relaying the connection.
     * ------------------------------------------------------------------ */

    format_sas(sas, sas_key);

    if (tui_mode){
        /* tui_init_term() was already called before TCP connection */
        int sas_ok = tui_sas_screen(sas);
        crypto_wipe(sas_key, sizeof sas_key);
        crypto_wipe(sas,     sizeof sas);
        if (!sas_ok){
            printf("\033[2J\033[H");
            printf("Aborted.\n");
            goto out;
        }

        tui_chat_loop(g_fd, &g_sess);
    } else {
    printf("\n");
    printf("+------------------------------------------+\n");
    printf("|  COMPARE THIS CODE WITH YOUR PEER        |\n");
    printf("|  before typing anything                  |\n");
    printf("+------------------------------------------+\n");
    printf("  Safety code:  %s\n\n", sas);
    printf("Call the peer on a separate channel and compare the code.\n");
    printf("If it does not match, press Ctrl+C now.\n\n");

    /* Ask the user to type the first 4 characters of the safety code
     * rather than just pressing y.  This breaks the muscle-memory habit
     * of blindly confirming prompts and proves they actually read the code.
     * The first 4 chars are the part before the dash, e.g. "A3F2" in "A3F2-91BC". */
    printf("Type the first 4 characters of the code to confirm: ");
    fflush(stdout);

    if (!fgets(typed_sas, sizeof typed_sas, stdin)){
        printf("Aborted.\n"); goto out;
    }
    /* Strip trailing newline, then compare case-insensitively against sas[0..3]. */
    { size_t yl = strlen(typed_sas); if (yl > 0 && typed_sas[yl-1] == '\n') typed_sas[yl-1] = '\0'; }
    if (
#if defined(_WIN32) || defined(_WIN64)
        _strnicmp(typed_sas, sas, 4) != 0
#else
        strncasecmp(typed_sas, sas, 4) != 0
#endif
    ){
        printf("Code mismatch -- aborted.\n"); goto out;
    }
    crypto_wipe(sas_key, sizeof sas_key);
    crypto_wipe(sas,     sizeof sas);

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

    printf("\nSecure session active.  Max message: %d bytes.  "
           "Ctrl+C to quit.\n\n", MAX_MSG);

    cli_chat_loop(g_fd, &g_sess);
    } /* end else (CLI mode) */

    g_running = 0;
    sock_shutdown_both(g_fd);
    close_sock(g_fd);
    g_fd = INVALID_SOCK;
    rc = 0;

out:
    /* Always reached.  Wiping uninitialised or already-zero variables is safe. */
    if (g_fd != INVALID_SOCK){ sock_shutdown_both(g_fd); close_sock(g_fd); }
    session_wipe(&g_sess);
    crypto_wipe(self_priv,    sizeof self_priv);
    crypto_wipe(self_pub,     sizeof self_pub);
    crypto_wipe(peer_pub,     sizeof peer_pub);
    crypto_wipe(commit_self,  sizeof commit_self);
    crypto_wipe(commit_peer,  sizeof commit_peer);
    crypto_wipe(sas_key,      sizeof sas_key);
    crypto_wipe(sas,          sizeof sas);
    crypto_wipe(typed_sas,    sizeof typed_sas);
    plat_quit();
    return rc;
}
