# SimpleCipher

P2P encrypted chat. Modular C protocol, cross-compiled to 5 targets.

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
├── tui.h/c             shared TUI (ring buffer, drawing, SAS screen)
├── tui_posix.c         POSIX TUI event loop (poll + raw termios)
├── tui_win.c           Windows TUI event loop (WaitForMultipleObjects)
├── cli.h/c             shared CLI (secure_chat_print)
├── cli_posix.c         POSIX CLI event loop (poll + cooked stdin)
└── cli_win.c           Windows CLI event loop + console helpers
lib/
├── monocypher.c        vendored crypto (do not modify)
└── monocypher.h        vendored API declarations
```

Consumers (main.c, test_p2p.c, jni_bridge.c) include headers and link object files. No #include .c pattern.

## Key rules

- `src/` contains all protocol logic — each module has a header and implementation
- `lib/monocypher.c/h` is vendored upstream — never modify
- All binaries must be fully static, zero runtime dependencies
- C23 standard, size-optimized (`-Os -flto`). OpenBSD 7.7 uses `-std=c2x` (Clang 16); `constexpr` compat shim in `platform.h`.
- Crypto: X25519, XChaCha20-Poly1305, BLAKE2b (all via Monocypher)
- Every key/secret must be wiped with `crypto_wipe()` after use
- `keygen` subcommand creates a passphrase-protected persistent identity key file; `--identity` loads it at runtime (prompts for passphrase)
- `--peer-fingerprint` works for both listen and connect (64-bit BLAKE2b hash of peer's public key)
- `--trust-fingerprint` (requires `--peer-fingerprint`): skips SAS when fingerprint matches — enables fully non-interactive mutual verification via pre-shared paper fingerprints
- Fingerprints are stable when using `keygen` + `--identity`; ephemeral (change every session) without them
- CI builds and tests natively on 8 runners (Linux/Windows x86_64/aarch64)
- Release: push a `v*` tag — CI builds, tests, publishes GitHub release

## Tests

`tests/test_p2p.c` — 769 tests, `tests/test_socks5_proxy.c` — 10 SOCKS5 proxy tests, `tests/test_cli_flags.sh` — 16 CLI flag integration tests (795 total) covering crypto, DH ratchet, TCP loopback handshake, bidirectional messaging, tamper detection, replay rejection, forward secrecy, post-compromise security, KDF known-answer vectors, constant-time verification, dudect timing smoke tests (ct_compare, is_zero32), SOCKS5 request building, peer fingerprint verification, identity key save/load, --peer-fingerprint, --trust-fingerprint, --identity, and keygen CLI flags, cover traffic, transactional ratchet receive, MAC failure tolerance. Must pass before any release.

Run with: `make test` (P2P tests only) and `make test-all` (all tests: P2P + SOCKS5 + CLI flags)
