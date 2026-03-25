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
    /* getentropy(3) is limited to 256 bytes per call on all BSDs.
     * Loop in chunks to support larger requests (e.g. test harnesses). */
    while (n > 0) {
        size_t chunk = n > 256 ? 256 : n;
        if (getentropy(b, chunk) != 0){ perror("getentropy"); _exit(1); }
        b += chunk;
        n -= chunk;
    }
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

#if defined(_WIN32) || defined(_WIN64)
void harden(void){
    /* Disable crash dumps (WER: Windows Error Reporting).
     * SEM_FAILCRITICALERRORS: suppress hard-error dialog boxes
     * SEM_NOGPFAULTERRORBOX: suppress WER crash dialogs + dump files
     * Together these prevent key material from being written to disk
     * via crash dump files when the process terminates abnormally. */
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
}
#else /* POSIX */
void harden(void){
    /* Best-effort: succeeds as root or with ulimit -l unlimited,
     * silently fails for unprivileged users (expected, not fatal). */
    (void)mlockall(MCL_CURRENT | MCL_FUTURE);
    /* Disable core dumps so a crash never writes key material to disk.
     * Set soft limit to 0 first (always allowed), then try to drop the
     * hard limit too (requires privilege — best-effort). */
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_CORE, &rl) == 0) {
            rl.rlim_cur = 0;
            setrlimit(RLIMIT_CORE, &rl);      /* soft = 0, keep hard */
            rl.rlim_max = 0;
            (void)setrlimit(RLIMIT_CORE, &rl); /* try hard = 0 too   */
        }
    }
  #ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
  #endif
}
#endif /* platform */

/* ---- seccomp-BPF syscall sandboxing (Linux only) ----------------------
 *
 * After the handshake completes and the chat loop is about to start,
 * the process only needs a handful of syscalls: read, write, poll, close,
 * exit, signal return, and timestamps.  Everything else (execve, fork,
 * connect, open, socket, etc.) is unnecessary and represents attack surface.
 *
 * Seccomp-BPF installs a kernel-level filter that kills the process if a
 * disallowed syscall is attempted.  Even if an attacker achieves code
 * execution (e.g. via a buffer overflow in a future bug), they cannot
 * spawn a shell, connect to another host, or read files.
 *
 * This is the same technique used by OpenSSH, Chrome, and Android.
 *
 * The filter is a BPF (Berkeley Packet Filter) program that examines each
 * syscall number and returns ALLOW or KILL_PROCESS. */
#if defined(__linux__)
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/syscall.h>

/* Detect the correct audit architecture for the BPF filter.
 * The seccomp filter checks the arch field to prevent syscall confusion
 * on multi-arch kernels (e.g. 32-bit compat on 64-bit). */
#if defined(__x86_64__)
  #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
  #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
  #undef SECCOMP_AUDIT_ARCH  /* skip seccomp on unknown arch */
#endif

#ifdef SECCOMP_AUDIT_ARCH

/* Helper: set PR_SET_NO_NEW_PRIVS and install a BPF filter.
 * Called once per phase.  Best-effort: if the kernel does not support
 * seccomp-BPF, the process continues with a wider syscall surface. */
static void apply_seccomp(struct sock_filter *f, unsigned short len){
    struct sock_fprog prog = { .len = len, .filter = f };
    /* PR_SET_NO_NEW_PRIVS is required before installing a seccomp filter
     * without CAP_SYS_ADMIN.  It prevents gaining privileges via execve
     * (setuid bits are ignored after this point). */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return;
    (void)prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

/* Phase 1 filter — handshake phase.
 *
 * Allows everything needed for the handshake: TCP socket setup, DNS
 * resolution, key generation, signal setup, and memory management.
 * Blocks exec, fork, open, and all other unneeded syscalls.
 *
 * Allowed syscalls:
 *   socket/connect/bind/listen/accept/accept4
 *                    — TCP connection setup
 *   read/write/writev — socket and terminal I/O
 *   sendto/recvfrom  — some libc TCP implementations use these
 *   poll/ppoll/select — I/O event loop
 *   close/shutdown   — socket cleanup
 *   getpeername/getsockname/getsockopt/setsockopt
 *                    — socket option queries (DNS, TCP_NODELAY)
 *   getrandom        — key generation (fill_random)
 *   mmap/munmap/mprotect/brk
 *                    — memory allocation (glibc/musl)
 *   rt_sigaction/sigaltstack
 *                    — signal handler installation
 *   rt_sigreturn     — return from signal handler (required by kernel)
 *   prctl            — PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS
 *   mlockall         — memory locking (harden())
 *   setrlimit/prlimit64
 *                    — disable core dumps (harden())
 *   clock_gettime/nanosleep/gettimeofday
 *                    — timing
 *   ioctl            — terminal mode changes
 *   exit/exit_group  — process termination
 *   futex            — glibc internal locking
 *   newfstatat/fstat — glibc internal (stdout detection)
 *   rseq             — restartable sequences (glibc 2.35+)
 *   fcntl            — socket flags (O_NONBLOCK for connect timeout)
 *
 * Phase 1 is installed AFTER the TCP connection is established.  It does
 * NOT allow socket/connect/bind/listen/accept — those are no longer needed.
 * A compromised process cannot open new connections from this point on.
 */
static void install_seccomp_phase1(void){
    struct sock_filter filter[] = {
        /* Architecture check */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        /* Existing-socket I/O only — no new connections.
         * shutdown is needed for graceful disconnect on error. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_shutdown,      0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        /* I/O */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read,          0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_writev,        0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto,        0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_recvfrom,      0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* SYS_poll does not exist on aarch64 (uses ppoll only) */
#ifdef SYS_poll
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_poll,          0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#endif
#ifdef SYS_select
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_select,        0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ppoll,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        /* Entropy and timing */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getrandom,     0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_gettime, 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_nanosleep,     0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#ifdef SYS_gettimeofday
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_gettimeofday,  0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#endif

        /* Memory management */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mmap,          0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_munmap,        0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mprotect,      0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_brk,           0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#ifdef SYS_mlock
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mlock,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mlockall,      0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        /* Signals */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigaction,  0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigreturn,  0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sigaltstack,   0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#ifdef SYS_rt_sigprocmask
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigprocmask,0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#endif

        /* Process control */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit,          0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group,    0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prlimit64,     0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#ifdef SYS_setrlimit
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_setrlimit,     0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#endif

        /* glibc/musl internals */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_futex,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_newfstatat,    0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* SYS_fstat does not exist on aarch64 (uses newfstatat only) */
#ifdef SYS_fstat
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fstat,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rseq,          0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        /* Default: kill the process on any disallowed syscall */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    apply_seccomp(filter, (unsigned short)(sizeof filter / sizeof filter[0]));
}

/* Phase 2 filter — chat loop phase.
 *
 * Tightened from phase 1: drops setup-only syscalls that were needed
 * between TCP connect and handshake completion but are no longer
 * required during the chat loop:
 *   select       — handshake may use it; chat loop uses poll only
 *   nanosleep    — timing only needed during handshake retry
 *   gettimeofday — superseded by clock_gettime in chat
 *   mlock/mlockall — memory locking done once in harden()
 *   rt_sigprocmask — signal mask setup done once
 *   prctl        — PR_SET_DUMPABLE done once in harden()
 *   setrlimit    — core dump disable done once in harden()
 *   fcntl        — socket O_NONBLOCK set during connect, not needed after
 *   exit         — only exit_group needed (exit is per-thread)
 *
 * After the handshake the process only needs I/O on already-open fds,
 * poll, getrandom (DH ratchet), and signal/exit handling.  Even if an
 * attacker achieves code execution they cannot open new connections,
 * exec a shell, or read files.
 *
 * Allowed syscalls (the minimum for poll-based encrypted chat):
 *   read/write       — socket and terminal I/O
 *   poll/ppoll       — event loop (wait for socket or stdin)
 *   close/shutdown   — socket cleanup on exit
 *   exit_group       — process termination
 *   rt_sigreturn     — return from signal handler (required by kernel)
 *   rt_sigaction     — glibc may re-issue during signal delivery
 *   clock_gettime    — timestamps for chat messages (via time())
 *   ioctl            — terminal mode changes (tcsetattr for TUI/CLI)
 *   mmap/munmap      — glibc/musl internal allocator (printf, etc.)
 *   mprotect         — glibc/musl internal use
 *   brk              — heap management (musl uses this)
 *   sendto/recvfrom  — some libc implementations use these for TCP
 *   futex            — glibc internal locking (printf, malloc)
 *   newfstatat/fstat — glibc internal use (stdout detection)
 *   getrandom        — fill_random for ratchet keypair generation
 *   writev           — some libc printf implementations use this
 *   sigaltstack      — signal stack setup (glibc)
 *   prlimit64        — getrlimit/setrlimit (musl)
 *   rseq             — restartable sequences (glibc 2.35+)
 */
static void install_seccomp_phase2(void){
    struct sock_filter filter[] = {
        /* Load the syscall architecture */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        /* Kill if wrong architecture */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* Load the syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        /* Allow each permitted syscall */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read,          0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_writev,        0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* SYS_poll does not exist on aarch64 (uses ppoll only) */
#ifdef SYS_poll
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_poll,          0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ppoll,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group,    0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigreturn,  0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigaction,  0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_gettime, 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mmap,          0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_munmap,        0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mprotect,      0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_brk,           0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto,        0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_recvfrom,      0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_futex,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_newfstatat,    0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* SYS_fstat does not exist on aarch64 (uses newfstatat only) */
#ifdef SYS_fstat
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fstat,         0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getrandom,     0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sigaltstack,   0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prlimit64,     0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rseq,          0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_shutdown,      0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        /* Default: kill the process on any disallowed syscall */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    apply_seccomp(filter, (unsigned short)(sizeof filter / sizeof filter[0]));
}
#endif /* SECCOMP_AUDIT_ARCH */
#endif /* __linux__ */

/* ---- FreeBSD Capsicum --------------------------------------------------- */

/* Capsicum is a capability-based sandbox built into the FreeBSD kernel.
 * Unlike seccomp (which filters syscall numbers), Capsicum restricts
 * operations on file descriptors.  cap_enter() is irreversible and blocks
 * ALL new fd creation (open, socket, accept).  Per-fd rights are narrowed
 * with cap_rights_limit() (rights can only be removed, never added).
 *
 * Syscalls that don't touch fds — arc4random_buf(), clock_gettime(),
 * sigaction(), exit() — work unconditionally in capability mode.
 * This makes Capsicum simpler than seccomp: no need to enumerate every
 * glibc/musl internal syscall.
 *
 * Phase 1: cap_enter() + generous per-fd rights (need setsockopt for
 *          handshake, ioctl for terminal setup).
 * Phase 2: narrow rights — drop setsockopt/getsockopt on the socket. */
#if defined(__FreeBSD__)
#include <sys/capsicum.h>

static void capsicum_phase1(int sock_fd){
    /* Enter capability mode — no new fds from this point on.
     * Idempotent: calling twice is a harmless no-op. */
    if (cap_enter() != 0) return;  /* best-effort (e.g. kernel w/o Capsicum) */

    /* Socket fd: read, write, poll, shutdown, get/setsockopt.
     * get/setsockopt is needed during handshake (TCP_NODELAY, SO_KEEPALIVE,
     * timeouts).  Phase 2 will drop these. */
    {
        cap_rights_t rights;
        cap_rights_init(&rights,
            CAP_READ, CAP_WRITE, CAP_EVENT,
            CAP_SHUTDOWN,
            CAP_SETSOCKOPT, CAP_GETSOCKOPT);
        cap_rights_limit(sock_fd, &rights);
    }

    /* stdin: read + poll + ioctl (terminal mode: TIOCGETA/TIOCSETA/TIOCGWINSZ) */
    {
        cap_rights_t rights;
        cap_rights_init(&rights, CAP_READ, CAP_EVENT, CAP_IOCTL);
        cap_rights_limit(STDIN_FILENO, &rights);
        unsigned long ioctls[] = { TIOCGETA, TIOCSETA, TIOCGWINSZ };
        cap_ioctls_limit(STDIN_FILENO, ioctls, 3);
    }

    /* stdout: write + ioctl (terminal mode queries, window size) */
    {
        cap_rights_t rights;
        cap_rights_init(&rights, CAP_WRITE, CAP_EVENT, CAP_IOCTL);
        cap_rights_limit(STDOUT_FILENO, &rights);
        unsigned long ioctls[] = { TIOCGETA, TIOCSETA, TIOCGWINSZ };
        cap_ioctls_limit(STDOUT_FILENO, ioctls, 3);
    }

    /* stderr: write only (error messages) */
    {
        cap_rights_t rights;
        cap_rights_init(&rights, CAP_WRITE);
        cap_rights_limit(STDERR_FILENO, &rights);
    }
}

static void capsicum_phase2(int sock_fd){
    /* Tighten socket rights: drop setsockopt/getsockopt — no longer needed
     * after handshake.  cap_rights_limit() only narrows, never widens. */
    cap_rights_t rights;
    cap_rights_init(&rights,
        CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SHUTDOWN);
    cap_rights_limit(sock_fd, &rights);
}
#endif /* __FreeBSD__ */

/* ---- sandbox entry points ----------------------------------------------- */

void sandbox_phase1(int sock_fd){
#if defined(CIPHER_HARDEN) && defined(__linux__) && defined(SECCOMP_AUDIT_ARCH)
    (void)sock_fd;
    install_seccomp_phase1();
#endif
#if defined(CIPHER_HARDEN) && defined(__FreeBSD__)
    capsicum_phase1(sock_fd);
#endif
#if defined(CIPHER_HARDEN) && defined(__OpenBSD__)
    (void)sock_fd;
    /* Lock filesystem access — no file paths needed at any phase. */
    unveil(NULL, NULL);
    /* TCP connection is already established.  Allow only I/O on existing
     * file descriptors + getrandom (for the handshake key exchange).
     * "inet" is NOT needed — we have the connected socket already. */
    pledge("stdio", NULL);
#endif
#if !defined(CIPHER_HARDEN) || (!defined(__linux__) && !defined(__FreeBSD__) && !defined(__OpenBSD__))
    (void)sock_fd;
#endif
}

void sandbox_phase2(int sock_fd){
#if defined(CIPHER_HARDEN) && defined(__linux__) && defined(SECCOMP_AUDIT_ARCH)
    (void)sock_fd;
    install_seccomp_phase2();
#endif
#if defined(CIPHER_HARDEN) && defined(__FreeBSD__)
    capsicum_phase2(sock_fd);
#endif
#if defined(CIPHER_HARDEN) && defined(__OpenBSD__)
    (void)sock_fd;
    /* Drop network setup and DNS — the session socket is already open.
     * "stdio" covers read, write, poll, close, and exit. */
    pledge("stdio", NULL);
#endif
#if !defined(CIPHER_HARDEN) || (!defined(__linux__) && !defined(__FreeBSD__) && !defined(__OpenBSD__))
    (void)sock_fd;
#endif
}

void sandbox(void){
    /* Legacy entry point — equivalent to phase 2 (chat-loop restriction).
     * Callers that have not been updated to the two-phase API still get the
     * full post-handshake restriction.  Pass -1 since Capsicum callers
     * should use sandbox_phase2(fd) directly. */
    sandbox_phase2(-1);
}

#else
void harden(void){}                    /* no-op when CIPHER_HARDEN is not set */
void sandbox_phase1(int sock_fd){ (void)sock_fd; }
void sandbox_phase2(int sock_fd){ (void)sock_fd; }
void sandbox(void){}
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

/* Best-effort terminal scrollback purge.
 * Emits ANSI escape sequences to clear the visible screen and scrollback
 * buffer.  Only effective when stdout is a terminal — silently skipped when
 * piping or redirecting. */
#if defined(_WIN32) || defined(_WIN64)
void purge_terminal(void){
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD mode;
    if (!GetConsoleMode(h, &mode)) return;  /* not a console */
    /* Windows 10+ supports ANSI sequences via ENABLE_VIRTUAL_TERMINAL_PROCESSING */
    if (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) {
        const char seq[] = "\033[2J\033[3J\033[H";
        DWORD written;
        WriteConsoleA(h, seq, sizeof seq - 1, &written, NULL);
    } else {
        /* Fallback: clear screen via Console API (no scrollback clear) */
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(h, &csbi)) {
            DWORD cells = csbi.dwSize.X * csbi.dwSize.Y;
            COORD origin = {0, 0};
            DWORD written;
            FillConsoleOutputCharacterA(h, ' ', cells, origin, &written);
            FillConsoleOutputAttribute(h, csbi.wAttributes, cells, origin, &written);
            SetConsoleCursorPosition(h, origin);
        }
    }
}
#else /* POSIX */
void purge_terminal(void){
    if (!isatty(STDOUT_FILENO)) return;
    /* \033[2J  — clear visible screen
     * \033[3J  — clear scrollback buffer (xterm, VTE, Windows Terminal)
     * \033[H   — move cursor to top-left */
    const char seq[] = "\033[2J\033[3J\033[H";
    (void)write(STDOUT_FILENO, seq, sizeof seq - 1);
}
#endif /* platform */

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
