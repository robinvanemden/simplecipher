# Platform Hardening and Verification — SimpleCipher

> **Audience:** Security auditors, penetration testers, and developers verifying the security posture of SimpleCipher binaries.

> SimpleCipher ships with many layers of protection built in — you don't need to configure anything. This document lists every security measure in detail, for auditors and developers who want to verify what's under the hood. **If you just want to chat securely, you don't need to read this** — see the [README](../README.md) to get started. For definitions of technical terms, see the [Glossary](GLOSSARY.md).

## Security notes

- **Keys are ephemeral.** If your device is seized after a session, past messages cannot be decrypted because the private key is already gone.
- **Deadline-aware I/O.** Handshake exchanges, SOCKS5 negotiation, and chat-phase frame reads/writes all use deadline-aware I/O that checks a monotonic clock between syscalls. SO_RCVTIMEO/SO_SNDTIMEO is set *before* the sandbox and never modified after — the deadline functions do not call setsockopt (which is blocked by seccomp phase 2). Maximum overshoot past a deadline is one SO_RCVTIMEO period (~30 seconds for chat, ~5 seconds for SOCKS5). Note: the initial TCP connect to a SOCKS5 proxy is still a blocking connect() not covered by the deadline — on desktop this is typically localhost (instant); on Android the connect is non-blocking with poll() and nativeStop() interrupt.
- **Runtime hardening** is enabled in all release builds (`-DCIPHER_HARDEN`). If seccomp or Capsicum sandbox installation fails at runtime, a warning is printed to stderr (the session continues without that layer). Use `--require-sandbox` to make sandbox failure fatal.

## Platform hardening

Every release binary includes compile-time and runtime hardening. Nothing is optional or requires special flags — this is what ships.

| Technique | Linux | Windows | Android |
|-----------|:-----:|:-------:|:-------:|
| **Compiler** | | | |
| [Stack canaries](GLOSSARY.md#stack-canary) (`-fstack-protector-strong`) | yes | yes | yes |
| Stack clash protection | yes | — | — |
| Zero-init all locals (`-ftrivial-auto-var-init=zero`) | yes | yes | yes |
| Buffer overflow detection (`_FORTIFY_SOURCE`) | 3 | — | 2 |
| Control-flow integrity | [CET](GLOSSARY.md#cet-control-flow-enforcement-technology) (x86), [BTI](GLOSSARY.md#bti-branch-target-identification) (arm64) | CET via mingw (`-fcf-protection=full`); no MSVC CFG PE flag | BTI (arm64) |
| Strict flex array bounds (`-fstrict-flex-arrays=3`) | yes | yes | — |
| Hidden symbol visibility | yes | yes | yes + JNI export whitelist |
| [LTO](GLOSSARY.md#lto-link-time-optimization) (whole-program optimization) | yes | yes | yes |
| **Linker** | | | |
| Full [RELRO](GLOSSARY.md#relro-relocation-read-only) (read-only GOT) | yes | — | yes |
| Non-executable stack | yes | — | yes |
| Block dlopen (`-z,nodlopen`) | yes | — | — |
| [ASLR](GLOSSARY.md#aslr-address-space-layout-randomization) | OS default | high-entropy | OS default |
| [DEP](GLOSSARY.md#dep-data-execution-prevention) ([W^X](GLOSSARY.md#wx-write-xor-execute)) | OS default | yes | OS default |
| Fully static binary | yes (musl) | yes | N/A (shared JNI lib) |
| Stripped symbols | yes | yes | yes |
| **Runtime** (`-DCIPHER_HARDEN`) | | | |
| Lock memory (prevent swap) | `mlockall` | — | — |
| Disable core dumps | `RLIMIT_CORE=0` | `SetErrorMode` (WER off) | `RLIMIT_CORE=0` (unconditional in JNI_OnLoad) |
| Block ptrace / memory inspection | `PR_SET_DUMPABLE=0` | — | `PR_SET_DUMPABLE=0` (unconditional in JNI_OnLoad) |
| [Seccomp](GLOSSARY.md#seccomp-secure-computing-mode)-BPF syscall filter (two-phase) | yes: phase 1 after TCP connect (blocks new sockets, ioctl restricted — TIOCSTI blocked), phase 2 after handshake (tightest, ioctl restricted — TIOCSTI blocked) | — | — |
| Process mitigation policies (Windows) | — | ProhibitDynamicCode, DisableExtensionPoints, StrictHandleCheck | — |
| [Capsicum](GLOSSARY.md#capsicum) capability sandbox (FreeBSD only) | — (FreeBSD: two-phase `cap_enter()` + per-fd rights, CI-verified) | — | — |
| [pledge/unveil](GLOSSARY.md#pledge--unveil) (OpenBSD only) | — (OpenBSD: `pledge("stdio")` + `unveil(NULL,NULL)`, CI-verified) | — | — |
| MAC failure tolerance (MAX_AUTH_FAILURES=3 — single forged frame does not kill session) | yes | yes | yes |
| **Key management** | | | |
| Wipe all keys after use (`crypto_wipe`) | yes | yes | yes (native layer) |
| Ephemeral keys only (nothing on disk) | yes | yes | yes |
| Passphrase-protected identity key (Argon2id, 100 MB, 3 passes) | yes | yes | — |
| **Android-specific** | | | |
| Block screenshots / screen recording | — | — | `FLAG_SECURE` |
| Block overlay windows (tapjacking) | — | — | `setHideOverlayWindows` |
| Custom in-app keyboard (no IME logging) | — | — | yes |
| Wipe UI widgets on background | — | — | yes |
| Kill session on app switch / lock | — | — | yes |
| Exclude from recent apps | — | — | yes |
| Disable backup / data extraction | — | — | yes |
| Strip all log calls in release | — | — | ProGuard/R8 |
| **Supply chain** | | | |
| CI actions pinned to commit SHAs | yes | yes | yes |
| Toolchain downloads verified by SHA256 | yes | yes | N/A (NDK from SDK manager) |
| Release APK signature verified before publish | — | — | yes (`apksigner verify`) |
| Sigstore build provenance attestation | yes | yes | yes |
| Vendored Monocypher integrity (SHA256 in CI) | yes | yes | yes |

### Sandbox lifecycle

The runtime sandbox tightens in phases. Each phase drops privileges that are no longer needed, so a vulnerability exploited later in the session has fewer syscalls available.

```
+-------------------------------------------------------+
|  Phase 0: Program start                               |
|  mlockall (RAM locked, no swap)                       |
|  RLIMIT_CORE=0 (no core dumps)                       |
|  PR_SET_DUMPABLE=0 (no ptrace attach)                 |
|  Windows: ProhibitDynamicCode, StrictHandleCheck       |
+---------------------------+---------------------------+
                            |
                            v
+-------------------------------------------------------+
|  Phase 1: After TCP connect                           |
|  Linux seccomp-BPF:                                   |
|    Blocked: socket, connect, bind, listen, accept,    |
|             open, execve, fork, ptrace                 |
|    Allowed: read, write, poll, nanosleep, mlock, ...  |
|  FreeBSD: cap_enter() + per-fd capability rights      |
|  OpenBSD: unveil(NULL,NULL) + pledge("stdio")         |
+---------------------------+---------------------------+
                            |
                            v
+-------------------------------------------------------+
|  Phase 2: After handshake (SAS verified)              |
|  Linux seccomp-BPF (tightest):                        |
|    Additionally drops: select, nanosleep,             |
|      gettimeofday, mlock, rt_sigprocmask, prctl      |
|    Only allowed: read, write, poll, clock_gettime,    |
|      close, exit_group, mmap/munmap/madvise           |
|  FreeBSD: Capsicum narrows fd rights (drops           |
|      setsockopt/getsockopt)                           |
|  OpenBSD: pledge("stdio") (unchanged)                 |
+---------------------------+---------------------------+
                            |
                            v
+-------------------------------------------------------+
|  Session end                                          |
|  crypto_wipe() all keys, chains, and ratchet state    |
|  Process exits cleanly                                |
+-------------------------------------------------------+
```

**Why phases matter:** A bug exploited during the chat phase (Phase 2) cannot open files, make new connections, or execute other programs — the kernel blocks the syscalls before they reach userspace. An attacker who compromises the process during chat can only read/write on the existing socket and exit.

## Verification stack

### Unit and integration tests (CI, blocking)

```bash
make test                      # 669 C tests (659 core + 10 SOCKS5)
bash tests/test_cli_flags.sh   # 16 CLI flag integration tests
```

Covers: crypto primitives, DH ratchet (roundtrip, rotation, PCS proof, simultaneous send), TCP loopback, tamper/replay/reserved-flag rejection, forward secrecy, KDF known-answer vectors, fingerprint verification, SOCKS5 request building, deterministic session vectors.

### Sanitizers (CI, blocking)

- **[AddressSanitizer](GLOSSARY.md#sanitizer)** + **[UndefinedBehaviorSanitizer](GLOSSARY.md#sanitizer)** on the full test suite (clang-19)
- **[MemorySanitizer](GLOSSARY.md#sanitizer)** — detects uninitialized memory reads

### Static analysis (CI, blocking)

- clang-tidy-19: bugprone, cert, security, clang-analyzer checks

### Fuzzing (CI smoke + weekly long runs)

- libFuzzer + ASan + UBSan on: frame parsing, input sanitization, port validation, SOCKS5 request building
- 4 fuzz targets in `tests/fuzz_*.c`

### Formal verification (manual)

Requires [CBMC](https://github.com/diffblue/cbmc).

```bash
python3 tests/cbmc_harness.py
```

Bounded model checking on 9 functions: `frame_open`, `frame_build`, `chain_step`, `ratchet_send`, `ratchet_receive`, `session_init`, `format_fingerprint`, `socks5_build_request`, `socks5_reply_skip`. Proves absence of buffer overflow, out-of-bounds access, null pointer dereference, and signed integer overflow for ALL possible inputs (57,161 properties verified).

### Constant-time verification (manual)

Two complementary tools that catch different classes of timing side channels:

| | Timecop/Valgrind | dudect |
|---|---|---|
| **Method** | Marks secrets as "uninitialized"; Valgrind flags any branch that depends on them | Runs function ~2M times; Welch's t-test detects timing correlations |
| **Catches** | Secret-dependent branches, secret-dependent array indexing | Variable-latency CPU instructions (cache, pipeline stalls) |
| **Cannot see** | Hardware timing differences (software CPU emulator) | Control-flow leaks if inputs don't exercise the right path |
| **Speed** | Seconds (deterministic) | Minutes (~2M measurements per function) |
| **When to use** | After any code change | Before release, new hardware targets |

All 8 secret-handling functions pass both tools: `is_zero32`, `verify_commit`, `domain_hash`, `expand`, `chain_step`, `crypto_x25519`, `frame_build`, `ct_compare`.

Known-accept: `frame_open` shows timing variance in dudect because Monocypher intentionally skips decryption on MAC failure (not exploitable — MAC comparison is [constant-time](GLOSSARY.md#constant-time)).

```bash
# Timecop (fast)
gcc -std=c23 -g -O1 -Isrc -Ilib tests/test_timecop.c \
  src/platform.c src/crypto.c src/protocol.c src/ratchet.c \
  src/network.c src/tui.c src/tui_posix.c src/cli.c \
  src/cli_posix.c lib/monocypher.c -lm -o test_timecop
valgrind --track-origins=yes ./test_timecop

# dudect (thorough)
gcc -std=c23 -O2 -Isrc -Ilib -Itests tests/test_constant_time.c \
  src/platform.c src/crypto.c src/protocol.c src/ratchet.c \
  src/network.c src/tui.c src/tui_posix.c src/cli.c \
  src/cli_posix.c lib/monocypher.c -lm -o test_ct
taskset -c 0 ./test_ct
```

### Platform binary tests (CI, blocking)

| Binary | Runners |
|--------|---------|
| Linux x86_64 | ubuntu-24.04, ubuntu-22.04 |
| Linux aarch64 | ubuntu-24.04-arm, ubuntu-22.04-arm |
| Windows x86_64 | windows-2025, windows-2022 |
| Windows aarch64 | windows-11-arm |
| FreeBSD x86_64 | Vultr bare-metal FreeBSD 14.3 (via SSH from GitHub Actions; when bare-metal hosts are configured) |
| OpenBSD x86_64 | Vultr bare-metal OpenBSD 7.7 (via SSH from GitHub Actions; when bare-metal hosts are configured) |
| Android APK | ubuntu-24.04 (structural validation + emulator smoke test: install, launch, UI navigation through listen/connect/fingerprint flows, pending-connect teardown, cold restart, native SOCKS5 loopback, and native P2P loopback — all checked for crashes via logcat) |
