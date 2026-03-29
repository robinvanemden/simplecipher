# Contributing to SimpleCipher

## Quick start

```bash
make && make test-all
```

This builds the project and runs all three test suites. If everything passes, your environment is ready.

## Requirements

- **C23 compiler**: GCC 13+ or Clang 17+ (Ubuntu 24.04+ works out of the box)
- OpenBSD 7.7 uses `-std=c2x` with Clang 16; a `constexpr` compat shim lives in `platform.h`

## Code formatting

`.clang-format` is enforced in CI. Before committing:

```bash
clang-format-19 -i src/*.c src/*.h
```

## Critical invariants

These are non-negotiable. Violating any of them will block your PR.

1. **Wipe every secret.** Every key or secret buffer must be wiped with `crypto_wipe()` after use -- on ALL code paths, including early error returns. No exceptions.

2. **Never use stdio for sensitive data.** Do not use `printf`/`fgets` for passphrases or keys. Use `write()`/`read()` directly to avoid libc's unwiped internal buffers.

3. **Update seccomp filters for new syscalls.** If your code introduces a new syscall, you must update the seccomp BPF filter in `platform.c` -- both phase 1 (pre-handshake) and phase 2 (post-handshake).

4. **Register new source files everywhere.** New `.c` files must be added to:
   - `Makefile`
   - `CMakeLists.txt`
   - All manual compile commands in `.github/workflows/build.yml` and `release.yml`

5. **Android has a separate source list.** The JNI build at `android/app/src/main/c/CMakeLists.txt` maintains its own file list. Only add files there if the JNI bridge actually uses them.

## Running the full test suite

`make test-all` runs all three suites:

| Suite | File | Tests |
|---|---|---|
| Core C tests | `tests/test_p2p.c` | 879 |
| SOCKS5 proxy | `tests/test_socks5_proxy.c` | 10 |
| CLI flags | `tests/test_cli_flags.sh` | 16 |

You can run them individually:

```bash
make test              # P2P tests only (test_p2p)
make test-all          # all tests: P2P + SOCKS5 + CLI flags
```

All tests must pass before any PR is merged.

## Pull requests

Follow the checklist in `.github/pull_request_template.md`. In short: describe what changed, confirm tests pass, and note any security-relevant implications.

## What not to touch

- `lib/monocypher.c` and `lib/monocypher.h` are vendored upstream. Never modify them.
