# Building and Development — SimpleCipher

> **Audience:** Developers who want to build from source, contribute, or understand the codebase structure.

## Quick build (native)

```bash
make
```

Or explicitly:

```bash
gcc -O2 -std=c23 -Isrc -Ilib src/*.c src/tui_posix.c src/cli_posix.c lib/monocypher.c -lm -o simplecipher
```

On OpenBSD 7.7 (Clang 16), use `-std=c2x` instead of `-std=c23`. A compatibility shim in `platform.h` maps the C23 `constexpr` keyword to `const` on older compilers.

## Cross-compile with CMake presets

Prerequisites: [musl cross-compilers](https://github.com/robinvanemden/toolchains/releases), [llvm-mingw](https://github.com/mstorsjo/llvm-mingw/releases), [Android NDK r28](https://developer.android.com/ndk).

```bash
# Linux x86_64 (static, musl)
cmake --preset linux-x86_64 && cmake --build --preset linux-x86_64

# Linux aarch64 (static, musl)
cmake --preset linux-aarch64 && cmake --build --preset linux-aarch64

# Windows x86_64 (static, UCRT)
cmake --preset win-x86_64 && cmake --build --preset win-x86_64

# Windows aarch64 (static, UCRT)
cmake --preset win-aarch64 && cmake --build --preset win-aarch64

# Android APK (arm64-v8a + armeabi-v7a)
cd android && ./gradlew assembleDebug
```

## Build flags

Binaries are size-optimized: `-Os -flto -ffunction-sections -fdata-sections` with `--gc-sections` for dead code removal. Linux binaries are stripped of symbols, build-id, and compiler ident. Full RELRO and non-executable stack are enabled on all ELF binaries.

See [HARDENING.md](HARDENING.md) for the complete list of security compiler and linker flags.

## Tests

```bash
# Run the P2P integration tests (696 tests)
make test

# Run the full local test suite (P2P + build + binary analysis)
bash tests/test_binary.sh
```

See [HARDENING.md](HARDENING.md) for the full verification stack (sanitizers, fuzzing, CBMC, constant-time).

## Code style

The C code follows **K&R style** (Kernighan & Ritchie), the standard for systems and crypto C:

- Opening brace on same line (`if (...) {`)
- 4-space indentation, no tabs
- `/* */` block comments only (no `//`)
- Pointer declaration: `int *p` (asterisk with the name)
- `snake_case` for functions and variables
- `UPPER_CASE` for constants (via `enum {}`)
- Column-aligned struct fields and BPF filter tables for readability
- Compact one-liner error handlers where the pattern is clear

The Java code (Android) follows standard Android/Google Java style: `camelCase` methods, `PascalCase` classes, 4-space indent.

Style is enforced by convention and review, not by automated formatting tools. The codebase uses intentional alignment (struct fields, seccomp tables, crypto wipe groups) that automated formatters destroy.

Configuration files: `.clang-format` (editor hint for new code), `.clang-tidy` (static analysis in CI), `.editorconfig` (editor defaults).

## Project structure

```
.
├── src/
│   ├── main.c                    # entry point — start reading here
│   ├── platform.h / platform.c   # OS abstraction: sockets, CSPRNG, signals, time
│   ├── crypto.h / crypto.c       # KDF, symmetric chain ratchet, commitment scheme
│   ├── ratchet.h / ratchet.c     # DH ratchet for post-compromise security
│   ├── protocol.h / protocol.c   # sessions, frame encrypt/decrypt, handshake helpers
│   ├── network.h / network.c     # TCP connect, listen, send, receive
│   ├── tui.h / tui.c             # shared TUI: ring buffer, drawing, SAS screen
│   ├── tui_posix.c               # POSIX TUI event loop (poll + raw termios)
│   ├── tui_win.c                 # Windows TUI event loop (WaitForMultipleObjects)
│   ├── cli.h / cli.c             # shared CLI: secure_chat_print
│   ├── cli_posix.c               # POSIX CLI event loop (poll + cooked stdin)
│   └── cli_win.c                 # Windows CLI event loop + console helpers
├── lib/
│   ├── monocypher.c              # vendored crypto library (public domain, do not modify)
│   └── monocypher.h              # monocypher API declarations
├── Makefile                      # quick native build: `make` / `make test`
├── CMakeLists.txt                # build config (C23, size-optimized, test target)
├── CMakePresets.json             # cross-compile presets (4 platforms)
├── cmake/toolchains/             # musl + llvm-mingw toolchain files
├── android/                      # Android app (JNI bridge + Java UI)
├── tests/
│   ├── test_p2p.c                # 696-test P2P integration suite
│   ├── test_constant_time.c      # dudect timing side-channel verification
│   ├── test_timecop.c            # Valgrind-based constant-time verification
│   ├── cbmc_harness.py           # CBMC formal verification (57K properties)
│   ├── fuzz_*.c                  # libFuzzer harnesses (4 targets)
│   ├── gen_fuzz_corpus.c         # seed corpus generator
│   └── test_*.sh / test_*.ps1   # platform binary analysis scripts
├── .clang-tidy                   # clang-tidy check configuration
└── .github/workflows/            # CI, fuzzing, release workflows
```

## Architecture

The protocol is split into focused modules. Each module exposes a header; consumers (`main.c`, `test_p2p.c`, `jni_bridge.c`) include the headers and link against the compiled object files.

```
lib/monocypher.c          (vendored crypto primitives — X25519, XChaCha20-Poly1305, BLAKE2b)
        │
src/platform.h/c          OS abstraction (sockets, CSPRNG, signals, sandboxing)
src/crypto.h/c            KDF, symmetric chain ratchet, commitment scheme
src/ratchet.h/c           DH ratchet (post-compromise security)
        │
src/protocol.h/c          sessions, frames, handshake helpers
src/network.h/c           TCP connect / listen / send / receive
src/tui.h/c               shared TUI (ring buffer, SAS screen)
src/cli.h/c               shared CLI (print helpers)
        │
src/tui_posix.c           ─┐
src/tui_win.c              ├─ platform-specific event loops
src/cli_posix.c            │
src/cli_win.c             ─┘
        │
src/main.c                entry point (links all of the above)
tests/test_p2p.c          integration test harness (links all except main.c)
android/…/jni_bridge.c   Android native bridge (links all except main.c)
```

Each module can be read and understood independently. `crypto.c` contains all cryptographic logic; `protocol.c` contains the session state machine; `network.c` handles TCP I/O. Nothing is hidden in a single monolithic file.

## Release process

Push a version tag to build on CI, test on all platforms, and publish a GitHub release with SHA256 checksums and Sigstore attestations:

```bash
git tag v0.5.0
git push origin v0.5.0
```

See [Verifying release binaries](../README.md#verifying-release-binaries) in the README.
