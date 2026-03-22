/*
 * platform.c — OS abstraction layer implementation for SimpleCipher
 *
 * Implements the portable platform API declared in platform.h.
 * All platform-specific code (Winsock init, CSPRNG, socket shutdown,
 * signal handling, process hardening) is contained here so the rest
 * of the codebase never touches OS APIs directly.
 */

#include "platform.h"

/* ---- global state ------------------------------------------------------- */

/* g_running is global because the signal handler writes it, and
 * volatile sig_atomic_t is the only type the C standard guarantees is
 * safe to write from a signal handler without data races. */
volatile sig_atomic_t g_running = 1;

#if defined(_WIN32) || defined(_WIN64)
volatile SOCKET g_interrupt_sock = INVALID_SOCKET;
#endif

/* ---- platform init/quit ------------------------------------------------- */

#if defined(_WIN32) || defined(_WIN64)

int  plat_init(void){ WSADATA w; return WSAStartup(MAKEWORD(2,2), &w); }
void plat_quit(void){ WSACleanup(); }

/* BCryptGenRandom: Windows CSPRNG, hardware-seeded.  Never use rand(). */
void fill_random(uint8_t *b, size_t n){
    if (BCryptGenRandom(nullptr, b, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG)){
        fprintf(stderr, "rng failed\n");
        ExitProcess(1);
    }
}

void sock_shutdown_both(socket_t s){ shutdown(s, SD_BOTH); }

#else /* POSIX */

int  plat_init(void){ return 0; }
void plat_quit(void){}

/* Cryptographically secure random bytes from the OS entropy pool.
 *
 * On Linux we prefer getrandom(2) (available since kernel 3.17): it blocks
 * until the pool is fully seeded, so it is safe at early boot and in
 * containers where /dev/urandom might not yet be available.
 *
 * On other POSIX systems (macOS, BSDs) we use getentropy(3), which has the
 * same blocking-until-seeded guarantee.
 *
 * /dev/urandom is used as a last resort because fopen() can succeed before
 * the pool is seeded on some minimal environments. */
void fill_random(uint8_t *b, size_t n){
#if defined(__linux__)
    if (getrandom(b, n, 0) != (ssize_t)n){ perror("getrandom"); _exit(1); }
#else
    if (getentropy(b, n) != 0){ perror("getentropy"); _exit(1); }
#endif
}

void sock_shutdown_both(socket_t s){ shutdown(s, SHUT_RDWR); }

#endif /* platform */

/* =========================================================================
 * OPTIONAL PROCESS HARDENING   (enable with: gcc -DCIPHER_HARDEN ...)
 *
 * Defence-in-depth against a compromised host.  Not part of the protocol.
 * Gated behind a flag so the default build stays simple and portable.
 *
 *   mlockall        -- prevents key pages from being swapped to disk
 *   RLIMIT_CORE = 0 -- disables core dumps (crash won't write keys to disk)
 *   PR_SET_DUMPABLE -- blocks ptrace / /proc/self/mem access (Linux only)
 * ========================================================================= */
#ifdef CIPHER_HARDEN
void harden(void){
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
        fprintf(stderr,
            "[warn] mlockall failed -- keys may appear in swap.\n"
            "       fix: run as root, or: ulimit -l unlimited\n");
    { struct rlimit z = {0,0}; setrlimit(RLIMIT_CORE, &z); }
  #ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
  #endif
}
#else
void harden(void){}   /* no-op when CIPHER_HARDEN is not set */
#endif

/* ---- signal handling ---------------------------------------------------- */

/* Signal handler: set the stop flag so the main loop exits on its next iteration.
 *
 * On POSIX, poll() is interrupted by signals and returns EINTR immediately.
 * The loop checks errno == EINTR, rechecks g_running, and exits cleanly.
 * No socket operations here -- shutdown() is not async-signal-safe.
 *
 * On Windows, WaitForMultipleObjects uses a 250 ms timeout, so g_running=0
 * is observed within one timeout period even without signal interruption. */
void on_sig(int sig){
    (void)sig;
    g_running = 0;
}

#if defined(_WIN32) || defined(_WIN64)
/* Windows console control handler: fires on Ctrl+C, console window close,
 * user logoff, and system shutdown.
 *
 * Runs in a NEW thread created by Windows.  We set g_running = 0 and
 * return TRUE so Windows does not terminate the process immediately.
 * The main thread's WaitForMultipleObjects (250 ms timeout) notices
 * g_running == 0, runs the cleanup path (crypto_wipe, session_wipe),
 * and exits cleanly before Windows' ~5-second forced-termination timer.
 *
 * Without this handler, closing the console window kills the process
 * instantly -- no cleanup, key material and chat plaintext linger in RAM
 * until the OS reclaims the pages. */
BOOL WINAPI on_console_ctrl(DWORD event){
    (void)event;
    g_running = 0;
    /* Close the socket the main thread is blocking on (accept, connect, recv).
     * This forces the blocking Winsock call to return with an error so the
     * main thread can check g_running and exit cleanly.  On POSIX, signals
     * deliver EINTR instead; Windows has no equivalent mechanism. */
    SOCKET s = g_interrupt_sock;
    if (s != INVALID_SOCKET) closesocket(s);
    return TRUE;
}
#endif

/* ---- helpers ------------------------------------------------------------ */

/* Write the current local time as "HH:MM:SS" into buf (size n).
 * Uses the thread-safe localtime_r (POSIX) / localtime_s (Windows).
 * Falls back to "??:??:??" if strftime cannot fit the result. */
void ts(char *buf, size_t n){
    time_t now = time(nullptr);
    struct tm tmv;
#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    if (strftime(buf, n, "%H:%M:%S", &tmv) == 0){
        strncpy(buf, "??:??:??", n);
        if (n) buf[n-1] = '\0';
    }
}

/* Encode a 64-bit integer in little-endian byte order.
 * Used to write sequence numbers into frames consistently on all platforms. */
void le64_store(uint8_t out[8], uint64_t v){
    int i;
    for (i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (8 * i));
}

/* Decode a little-endian 64-bit integer from bytes. */
uint64_t le64_load(const uint8_t in[8]){
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v |= ((uint64_t)in[i]) << (8 * i);
    return v;
}
