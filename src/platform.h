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
#    define _GNU_SOURCE
#endif
/* _POSIX_C_SOURCE enables POSIX APIs on Linux/glibc (localtime_r, etc.).
 * On OpenBSD, defining it HIDES BSD extensions (pledge, unveil, getentropy)
 * and __BSD_VISIBLE does not override it.  So skip it on OpenBSD entirely —
 * OpenBSD's headers expose POSIX APIs by default. */
#if !defined(__OpenBSD__)
#    ifndef _POSIX_C_SOURCE
#        define _POSIX_C_SOURCE 200809L
#    endif
#endif
/* On FreeBSD, _POSIX_C_SOURCE hides BSD extensions like getentropy().
 * __BSD_VISIBLE re-exposes them without removing POSIX declarations. */
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#    ifndef __BSD_VISIBLE
#        define __BSD_VISIBLE 1
#    endif
#endif

/* constexpr is C23.  GCC 13+ supports it with -std=c2x, but Clang 16
 * (OpenBSD 7.7) does not.  We cannot #define constexpr to const because
 * const int is NOT a constant expression in C and cannot size arrays in
 * structs.  Instead, we use enum for integer constants (always constant
 * expressions) and static const for uint8_t.  No shim needed — the
 * headers below use enum/const directly for portability across all
 * compilers including Clang 16. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <stdatomic.h>
#include <time.h>
#include <errno.h>

#if defined(_WIN32) || defined(_WIN64)
#    define WIN32_LEAN_AND_MEAN
#    include <winsock2.h>
#    include <ws2tcpip.h>
#    include <windows.h>
#    include <bcrypt.h>
#    include <iphlpapi.h> /* GetAdaptersAddresses — list local IPs */
#else
#    include <sys/socket.h>
#    include <netinet/in.h>
#    include <arpa/inet.h>
#    include <netdb.h>
#    include <unistd.h>
#    include <poll.h>
#    include <netinet/tcp.h> /* TCP_NODELAY */
#    include <ifaddrs.h>     /* getifaddrs — list local IP addresses */
#    ifdef __linux__
#        include <sys/random.h> /* getrandom(2) */
#    endif
#    ifdef CIPHER_HARDEN
#        include <sys/mman.h>
#        include <sys/resource.h>
#        ifdef __linux__
#            include <sys/prctl.h>
#        endif
#    endif
#endif

/* MSG_NOSIGNAL tells send() not to raise SIGPIPE if the peer closes.
 * Without it, a dropped peer would crash the process on Linux.
 * Windows has no SIGPIPE, so we define it as 0 (no-op flag). */
#ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
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
#    define INVALID_SOCK INVALID_SOCKET
#    define close_sock(s) closesocket(s)

#else /* POSIX */

typedef int socket_t;
#    define INVALID_SOCK (-1)
#    define close_sock(s) close(s)

#endif /* platform */

/* g_running is written from signal handlers (POSIX) and from the console
 * control handler thread (Windows).  volatile sig_atomic_t satisfies the
 * C standard's signal-handler requirement.  _Atomic adds proper memory
 * ordering for the Windows thread case and for ARM64 where volatile alone
 * does not imply acquire/release semantics. */
extern _Atomic volatile sig_atomic_t g_running;

#if defined(_WIN32) || defined(_WIN64)
/* g_interrupt_sock is set to the currently blocking socket (accept, connect,
 * recv) so the Windows console control handler can closesocket() it from
 * its separate thread, forcing the blocking call to return with an error.
 * _Atomic eliminates the TOCTOU race where the handler reads the socket
 * while the main thread is clearing it.  On POSIX, signals deliver EINTR
 * to blocking calls instead; this variable is not used. */
extern _Atomic volatile SOCKET g_interrupt_sock;
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

/* If non-zero, sandbox installation failure is fatal (exit instead of warn).
 * Set by --require-sandbox before any sandbox call. */
extern int g_require_sandbox;

/* Two-phase syscall sandboxing.  Return 0 on success or if sandboxing
 * is unavailable and g_require_sandbox is not set.  Return -1 if
 * g_require_sandbox is set and installation failed (caller must wipe
 * state and exit cleanly — the sandbox functions do NOT call _exit).
 *
 * sandbox_phase1(sock_fd) — call AFTER the TCP connection is established,
 *   BEFORE the handshake.  Connection setup (getifaddrs, getaddrinfo,
 *   socket, connect, bind, listen, accept) runs unrestricted.  Phase 1
 *   blocks new connections — a compromised process cannot open additional
 *   sockets.
 *   On Linux (seccomp-BPF): allows read, write, close, poll/ppoll, getrandom,
 *   mmap/mprotect/brk, sigaction, exit/exit_group, clock_gettime, nanosleep,
 *   ioctl, shutdown.  Does NOT allow socket, connect, bind, listen, accept.
 *   On FreeBSD (Capsicum): cap_enter() + per-fd rights on sock_fd and
 *   stdin/stdout/stderr.  No new file descriptors can be created.
 *   On OpenBSD: pledge("stdio") + unveil(NULL, NULL).
 *   No-op on other platforms or when CIPHER_HARDEN is not set.
 *
 * sandbox_phase2(sock_fd) — call after handshake completes, before the
 *   chat loop.  Tightens further: on Linux drops setup-only syscalls;
 *   on FreeBSD narrows per-fd Capsicum rights (removes setsockopt/
 *   getsockopt).  After the handshake the process only needs read/write
 *   on existing fds, poll, getrandom, and exit.
 *   On OpenBSD: pledge("stdio", NULL).
 *   No-op on other platforms or when CIPHER_HARDEN is not set.
 *
 * The sock_fd parameter is the connected session socket.  Capsicum needs
 * it to set per-fd capability rights; Linux seccomp and OpenBSD pledge
 * ignore it (they operate at the syscall/process level).
 *
 */
[[nodiscard]] int sandbox_phase1(int sock_fd);
[[nodiscard]] int sandbox_phase2(int sock_fd);

/* Signal handler: set the stop flag so the main loop exits on its next
 * iteration.  See platform.c for details on POSIX vs Windows behavior. */
void on_sig(int sig);

#if defined(_WIN32) || defined(_WIN64)
/* Windows console control handler: fires on Ctrl+C, console window close,
 * user logoff, and system shutdown.  See platform.c for full explanation. */
BOOL WINAPI on_console_ctrl(DWORD event);
#endif

/* Buffer size for "HH:MM:SS" timestamp strings (including NUL). */
enum { TIMESTAMP_BUF = 16 };

/* Write the current local time as "HH:MM:SS" into buf (size n).
 * Uses the thread-safe localtime_r (POSIX) / localtime_s (Windows). */
void format_timestamp(char *buf, size_t n);

/* Encode a 64-bit integer in little-endian byte order.
 * Used to write sequence numbers into frames consistently on all platforms. */
void le64_store(uint8_t out[8], uint64_t v);

/* Decode a little-endian 64-bit integer from bytes. */
uint64_t le64_load(const uint8_t in[8]);

/* Monotonic millisecond clock for timing decisions (not for crypto).
 * Uses CLOCK_MONOTONIC on POSIX, GetTickCount64 on Windows. */
uint64_t monotonic_ms(void);

/* Best-effort terminal scrollback purge.  Emits ANSI escape sequences
 * to clear the visible screen and scrollback buffer.  Only effective
 * when stdout is a terminal — silently skipped when piping or redirecting.
 * Not all terminals support \033[3J (scrollback clear), but it's harmless
 * where unsupported. */
void purge_terminal(void);

#endif /* SIMPLECIPHER_PLATFORM_H */
