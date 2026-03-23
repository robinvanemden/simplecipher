/*
 * platform.h — OS abstraction layer for SimpleCipher
 *
 * This module hides the differences between POSIX (Linux, macOS, BSD) and
 * Windows behind a single set of types and function names.  Every other
 * module includes this header and never touches platform-specific APIs
 * directly.
 *
 * What this provides:
 *   - A portable socket type (socket_t) and close macro
 *   - Cryptographically secure random bytes (fill_random)
 *   - Platform init/quit for Winsock
 *   - Signal handling helpers
 *   - Timestamp, endianness, and process hardening utilities
 *
 * Read next: crypto.h (cryptographic building blocks)
 */

#ifndef SIMPLECIPHER_PLATFORM_H
#define SIMPLECIPHER_PLATFORM_H

/* Feature-test macros must come before any system headers.
 * _GNU_SOURCE unlocks localtime_r and other POSIX extensions on Linux.
 * The #ifndef guards prevent "macro redefined" warnings if the compiler
 * already defines them via -D. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#if defined(_WIN32) || defined(_WIN64)
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <bcrypt.h>
  #include <iphlpapi.h>     /* GetAdaptersAddresses — list local IPs */
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <poll.h>
  #include <netinet/tcp.h>  /* TCP_NODELAY */
  #include <ifaddrs.h>      /* getifaddrs — list local IP addresses */
  #ifdef __linux__
    #include <sys/random.h>  /* getrandom(2) */
  #endif
  #ifdef CIPHER_HARDEN
    #include <sys/mman.h>
    #include <sys/resource.h>
    #ifdef __linux__
      #include <sys/prctl.h>
    #endif
  #endif
#endif

/* MSG_NOSIGNAL tells send() not to raise SIGPIPE if the peer closes.
 * Without it, a dropped peer would crash the process on Linux.
 * Windows has no SIGPIPE, so we define it as 0 (no-op flag). */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* =========================================================================
 * PLATFORM ABSTRACTION
 *
 * Windows and POSIX use different types and APIs for sockets and random
 * numbers.  We wrap the differences here once; all code above and below
 * is platform-agnostic.
 *
 * Threads and mutexes are gone entirely.
 * POSIX uses poll(); Windows uses WaitForMultipleObjects() on a
 * console input handle plus a Winsock event object.  Both paths are
 * single-threaded event loops.
 * ========================================================================= */
#if defined(_WIN32) || defined(_WIN64)

  /* On 64-bit Windows, SOCKET is UINT_PTR (8 bytes), not int (4 bytes).
   * Storing a socket in int silently truncates handles > 0x7FFFFFFF. */
  typedef SOCKET socket_t;
  #define INVALID_SOCK  INVALID_SOCKET
  #define close_sock(s) closesocket(s)

#else /* POSIX */

  typedef int socket_t;
  #define INVALID_SOCK  (-1)
  #define close_sock(s) close(s)

#endif /* platform */

/* g_running is global because the signal handler writes it, and
 * volatile sig_atomic_t is the only type the C standard guarantees is
 * safe to write from a signal handler without data races. */
extern volatile sig_atomic_t g_running;

#if defined(_WIN32) || defined(_WIN64)
/* g_interrupt_sock is set to the currently blocking socket (accept, connect,
 * recv) so the Windows console control handler can closesocket() it from
 * its separate thread, forcing the blocking call to return with an error.
 * On POSIX this is unnecessary: signals deliver EINTR to blocking calls. */
extern volatile SOCKET g_interrupt_sock;
#endif

/* Platform initialization and cleanup.
 * plat_init() starts Winsock on Windows; no-op on POSIX.
 * plat_quit() calls WSACleanup on Windows; no-op on POSIX. */
int  plat_init(void);
void plat_quit(void);

/* Cryptographically secure random bytes from the OS entropy pool.
 * See platform.c for the per-platform implementation details. */
void fill_random(uint8_t *b, size_t n);

/* Shut down both directions of a socket (read + write). */
void sock_shutdown_both(socket_t s);

/* Optional process hardening (mlockall, disable core dumps, block ptrace).
 * Enabled by compiling with -DCIPHER_HARDEN. No-op otherwise. */
void harden(void);

/* Optional syscall sandboxing (seccomp-BPF on Linux).
 * Call AFTER network setup and handshake, BEFORE the chat loop.
 * Restricts the process to only the syscalls needed for encrypted chat:
 * read, write, poll, close, exit, signal handling, timestamps.
 * If the process is exploited, the attacker cannot exec, fork, connect,
 * or open files.  No-op on non-Linux or when CIPHER_HARDEN is not set. */
void sandbox(void);

/* Signal handler: set the stop flag so the main loop exits on its next
 * iteration.  See platform.c for details on POSIX vs Windows behavior. */
void on_sig(int sig);

#if defined(_WIN32) || defined(_WIN64)
/* Windows console control handler: fires on Ctrl+C, console window close,
 * user logoff, and system shutdown.  See platform.c for full explanation. */
BOOL WINAPI on_console_ctrl(DWORD event);
#endif

/* Write the current local time as "HH:MM:SS" into buf (size n).
 * Uses the thread-safe localtime_r (POSIX) / localtime_s (Windows). */
void ts(char *buf, size_t n);

/* Encode a 64-bit integer in little-endian byte order.
 * Used to write sequence numbers into frames consistently on all platforms. */
void le64_store(uint8_t out[8], uint64_t v);

/* Decode a little-endian 64-bit integer from bytes. */
uint64_t le64_load(const uint8_t in[8]);

#endif /* SIMPLECIPHER_PLATFORM_H */
