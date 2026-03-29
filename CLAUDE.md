# SimpleCipher

P2P encrypted chat. Modular C protocol, compiled to 7 targets.

## Build

```bash
# Native (quick)
make

# Or explicitly:
gcc -O2 -std=c23 -DCIPHER_HARDEN -Isrc -Ilib src/main.c src/platform.c src/crypto.c src/protocol.c src/ratchet.c src/network.c src/tui.c src/cli.c src/args.c src/verify.c src/tui_posix.c src/cli_posix.c lib/monocypher.c -lm -o simplecipher

# Cross-compile (Linux/Windows, 4 presets)
cmake --preset linux-x86_64 && cmake --build --preset linux-x86_64

# Android
cd android && ./gradlew assembleDebug

# Tests
make test
```

## Architecture

```
src/
├── main.c              entry point
├── args.h/c            CLI config struct, exit codes, parse_args()
├── verify.h/c          passphrase input, keygen, fingerprint, SAS verify
├── platform.h/c        OS abstraction (sockets, random, signals, time, sandboxing)
├── crypto.h/c          KDF, symmetric chain ratchet, commitment scheme
├── ratchet.h/c         DH ratchet (post-compromise security)
├── protocol.h/c        sessions, frames, handshake helpers
├── network.h/c         TCP connect, listen, send, receive
├── nb_io.h/c           non-blocking frame I/O state machine (POSIX chat loops)
├── tui.h/c             shared TUI (ring buffer, drawing, SAS screen)
├── tui_posix.c         POSIX TUI event loop (poll + raw termios)
├── tui_win.c           Windows TUI event loop (WaitForMultipleObjects)
├── cli.h/c             shared CLI (secure_chat_print)
├── cli_posix.c         POSIX CLI event loop (raw termios + cooked fallback)
└── cli_win.c           Windows CLI event loop + console helpers
lib/
├── monocypher.c        vendored crypto (do not modify)
└── monocypher.h        vendored API declarations
```

Consumers (main.c, test_p2p.c, jni_bridge.c) include headers and link object files. No #include .c pattern.

## Key rules

- `src/` contains all protocol logic — each module has a header and implementation
- `lib/monocypher.c/h` is vendored upstream — never modify
- All binaries must be fully static, zero runtime dependencies (macOS: only libSystem.B.dylib)
- C23 standard, size-optimized (`-Os -flto`). Makefile auto-detects compiler capabilities via `cc_ok()` — falls back to `-std=c2x` on Apple Clang and older compilers. `constexpr`/`nullptr` compat shims in `platform.h`.
- Crypto: X25519, XChaCha20-Poly1305, BLAKE2b (all via Monocypher)
- Every key/secret must be wiped with `crypto_wipe()` after use
- `keygen` subcommand creates a passphrase-protected persistent identity key file; `--identity` loads it at runtime (prompts for passphrase)
- `--peer-fingerprint` works for both listen and connect (64-bit BLAKE2b hash of peer's public key)
- `--trust-fingerprint` (requires `--peer-fingerprint`): skips SAS when fingerprint matches — enables fully non-interactive mutual verification via pre-shared paper fingerprints
- Fingerprints are stable when using `keygen` + `--identity`; ephemeral (change every session) without them
- CI: 5 separate workflows for fast, clear feedback:
  - `build.yml` — cross-compile Linux/Windows/macOS/Android
  - `test.yml` — protocol tests (P2P, SOCKS5, TUI, CLI flags)
  - `security.yml` — ASan/UBSan/MSan, fuzz, static analysis
  - `platform.yml` — binary validation on Linux, Windows, macOS, FreeBSD, OpenBSD, ARM64
  - `android.yml` — emulator smoke test
- Release: push a `v*` tag — `release.yml` builds, tests, signs (Sigstore), publishes GitHub release

## Tests

`tests/test_p2p.c` — 1011 tests, `tests/test_socks5_proxy.c` — 10 SOCKS5 proxy tests, `tests/test_cli_flags.sh` — 16 CLI flag integration tests (1037 total) covering crypto, DH ratchet, TCP loopback handshake, bidirectional messaging, tamper detection, replay rejection, forward secrecy, post-compromise security (including staged ratchet state lifecycle), KDF known-answer vectors, constant-time verification, dudect timing smoke tests (ct_compare, is_zero32), SOCKS5 request building and buffer wipe verification, peer fingerprint verification, identity key save/load, --peer-fingerprint, --trust-fingerprint, --identity, and keygen CLI flags, cover traffic, TUI_ME_QUEUED display, inbound frame rate limiting (50/sec), non-blocking I/O (byte-by-byte accumulation, partial send drain, deadline checks, cover frame send, disconnect detection, send error cleanup, multi-frame accumulation, drain incomplete, wipe zeroing, cover-then-real interleave), cooked-mode multi-line pipe parsing, transactional ratchet receive, MAC failure tolerance. Must pass before any release.

Run with: `make test` (P2P tests only) and `make test-all` (all tests: P2P + SOCKS5 + CLI flags)
