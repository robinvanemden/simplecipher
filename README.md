# SimpleCipher

[![CI](https://github.com/robinvanemden/simplecipher/actions/workflows/ci.yml/badge.svg)](https://github.com/robinvanemden/simplecipher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Encrypted peer-to-peer chat in C. No server. No account. No dependencies.

Two people run the program, compare a short safety code over the phone, and start talking. Everything is encrypted, authenticated, and forward-secret. When the session ends, the keys are gone — even if someone recorded the entire conversation, they cannot decrypt it after the fact.

The protocol is implemented across a handful of focused C modules, designed to be audited in an afternoon. SimpleCipher is built for privacy and for teaching.

## Download

Grab a binary from the [latest release](https://github.com/robinvanemden/simplecipher/releases/latest) and run it. Nothing to install.

| Platform | Download | Size |
|----------|----------|------|
| Linux x86_64 | [simplecipher-linux-x86_64](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-linux-x86_64) | ~87 KB |
| Linux aarch64 | [simplecipher-linux-aarch64](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-linux-aarch64) | ~91 KB |
| Windows x86_64 | [simplecipher-win-x86_64.exe](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-win-x86_64.exe) | ~65 KB |
| Windows aarch64 | [simplecipher-win-aarch64.exe](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-win-aarch64.exe) | ~58 KB |
| Android (arm64 + armv7) | [simplecipher-android.apk](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-android.apk) | ~164 KB |

All desktop binaries are fully static with zero runtime dependencies.

## Quick start

The easiest way to chat across different networks is with [Tailscale](https://tailscale.com/) (free for personal use, 2-minute setup). Tailscale creates a WireGuard mesh so your devices can reach each other. SimpleCipher encrypts on top of that — ephemeral keys, SAS verification, and forward secrecy that Tailscale alone does not provide.

```bash
# Both devices: install Tailscale (one-time)
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up

# Person A: listen for a connection
simplecipher listen

# Person B: connect using Person A's Tailscale IP
simplecipher connect 100.x.y.z
```

On the same Wi-Fi or LAN, skip Tailscale entirely — just use the local IP:

```bash
# Person A
simplecipher listen

# Person B
simplecipher connect 192.168.1.42
```

### Other ways to connect

SimpleCipher encrypts your messages, but your IP address is still visible to the network. The transport you choose determines who can see that you're connecting:

| Method | When to use | Who sees your IP |
|--------|-------------|------------------|
| **LAN / Wi-Fi** | Same network | Nobody outside the network |
| **Tailscale** (easiest) | Different networks, quick setup | Tailscale's coordination server sees both endpoints |
| **WireGuard** | Manual VPN tunnel between devices | Your VPN peer only |
| **Port forwarding** | Forward port 7777 on your router | Anyone who knows the IP can attempt a connection |
| **Tor** | Anonymity matters | Neither side learns the other's IP; network observers see Tor traffic but not the destination |

**If you need anonymity** — not just encryption — use Tor. Install Tor, then: `torsocks simplecipher listen` and `torsocks simplecipher connect <onion-address>`. This also solves NAT traversal (no port forwarding needed).

### Options

```bash
# Specify a custom port (default: 7777)
simplecipher listen 9000
simplecipher connect 100.x.y.z 9000

# Split-pane terminal UI with scrolling messages and fixed input line
simplecipher --tui listen
simplecipher --tui connect 100.x.y.z
```

TUI mode works on Linux, macOS, and Windows 10+. No dependencies — pure ANSI escape sequences.

On Android, the same flow happens through the app UI: choose Listen or Connect, enter the host/port, verify the safety code, and chat.

### Safety code verification

After connecting, both sides see the same safety code:

```
+------------------------------------------+
|  COMPARE THIS CODE WITH YOUR PEER        |
|  before typing anything                  |
+------------------------------------------+
  Safety code:  A3F2-91BC

Type the first 4 characters of the code to confirm:
```

Call your peer on a separate channel (phone, in person) and compare the code. If it matches, type the first 4 characters to confirm. If it does not match, someone is intercepting — press Ctrl+C.

**The safety code comparison IS the authentication.** Skip it and a man-in-the-middle can read everything.

## How it works

SimpleCipher implements a complete encrypted chat protocol across a handful of focused C modules. Here is what happens when two people connect:

### 1. Key exchange

Each side generates a random X25519 keypair for this session only. The private key never leaves the machine. Through the mathematics of elliptic-curve Diffie-Hellman, both sides compute the same shared secret without ever transmitting it.

### 2. Commitment scheme (anti-MITM)

Before revealing public keys, each side sends a hash (commitment) of their key. This prevents a man-in-the-middle from seeing one key and then crafting a fake key that produces a matching safety code. The commitment locks both sides into their keys before the reveal.

```
Round 1:  Alice -> H(key_A)    Bob -> H(key_B)     (commitments)
Round 2:  Alice -> key_A       Bob -> key_B         (reveals)
Verify:   H(revealed_key) == commitment             (both sides)
```

### 3. Safety code verification

A short authentication string (SAS) is derived from the shared secret and displayed as `XXXX-XXXX`. Both people compare this code out-of-band (phone call, in person). A 32-bit code space is sufficient because the commitment scheme prevents brute-force search.

### 4. Encrypted messaging with forward secrecy and post-compromise security

Messages are encrypted with XChaCha20-Poly1305 using a two-layer ratchet:

**Layer 1 — Symmetric chain ratchet (forward secrecy):**

Each message derives a fresh encryption key from the current chain key, then the chain steps forward and the old key is wiped. Compromising one key reveals nothing about past messages.

```
chain[0]  -->  message_key[0]  (encrypt message 0, then wipe)
   |
chain[1]  -->  message_key[1]  (encrypt message 1, then wipe)
   |
chain[2]  -->  ...
```

**Layer 2 — DH ratchet (post-compromise security):**

When the conversation direction switches (Alice was listening, now she replies), the sender generates a fresh X25519 keypair and mixes the new shared secret into a root key. This derives a completely new chain that an attacker cannot predict, even if they stole the old chain key.

```
Alice sends  ──►  DH ratchet  ──►  new tx chain  ──►  symmetric ratchet
Bob replies  ──►  DH ratchet  ──►  new tx chain  ──►  symmetric ratchet
Alice sends  ──►  DH ratchet  ──►  new tx chain  ──►  symmetric ratchet
```

Together, this is the same "Double Ratchet" architecture that Signal uses: forward secrecy (past messages stay safe) plus post-compromise security (future messages recover after key theft).

### 5. Fixed-size framing

Every frame is exactly 512 bytes regardless of message length:

```
[ sequence: 8 bytes | ciphertext: 488 bytes | MAC: 16 bytes ]
```

This hides message length from network observers. The sequence number is authenticated (tamper-proof) but not encrypted, enabling replay and reorder detection before any crypto work.

## Security properties

| Property | How |
|----------|-----|
| **Confidentiality** | XChaCha20-Poly1305 authenticated encryption |
| **Key agreement** | X25519 ephemeral Diffie-Hellman |
| **Authentication** | Commit-then-reveal SAS verified out-of-band |
| **Forward secrecy** | Chain-key ratchet; each message key is used once then wiped |
| **Integrity** | Poly1305 MAC detects any tampering; sequence numbers reject replays |
| **Message-length hiding** | Fixed 512-byte frames prevent length-based analysis |
| **Terminal safety** | Peer messages are sanitized (non-printable bytes replaced with `.`) |
| **Post-compromise security** | DH ratchet mixes fresh X25519 entropy on each direction switch |
| **Ephemeral keys** | New keypair every session; nothing stored to disk |

### What it does NOT provide

- **Post-compromise security is per-session**: the DH ratchet recovers from key theft within a session, but there is no cross-session recovery. Each session starts fresh — if an attacker is present at session start, the entire session is compromised. This is inherent to the ephemeral design.
- **Anonymity**: IP addresses are visible on the network. For anonymity, run over Tor: `torsocks simplecipher connect ...`
- **Identity persistence**: there are no long-term keys or contacts. Each session is independent. This is deliberate — a stored identity key is a forensic artifact (proof you use the tool, and a target for impersonation if seized). The SAS verification on every connect *is* the identity model: human-verified, not key-pinned, and it leaves nothing on disk. If you need persistent contacts with key pinning, use Signal.
- **Android memory hygiene**: the desktop builds use `crypto_wipe()` on every buffer to ensure plaintext and keys do not linger in RAM. The Android build runs on the JVM, where Strings are immutable and garbage-collected — sensitive data cannot be reliably zeroed. The app clears widgets and blocks screenshots (`FLAG_SECURE`), but this is best-effort. For the strongest memory guarantees, use the desktop CLI or TUI.

### Security notes

- **Keys are ephemeral.** If your device is seized after a session, past messages cannot be decrypted because the private key is already gone.
- **The handshake has a 30-second timeout.** A peer who stalls during key exchange is disconnected automatically.
- **Runtime hardening** is enabled in all release builds (`-DCIPHER_HARDEN`). See the table below.

### Platform hardening

Every release binary includes compile-time and runtime hardening. Nothing is optional or requires special flags — this is what ships.

| Technique | Linux | Windows | Android |
|-----------|:-----:|:-------:|:-------:|
| **Compiler** | | | |
| Stack canaries (`-fstack-protector-strong`) | yes | yes | yes |
| Stack clash protection | yes | — | yes |
| Zero-init all locals (`-ftrivial-auto-var-init=zero`) | yes | yes | yes |
| Buffer overflow detection (`_FORTIFY_SOURCE`) | 3 | — | 2 |
| Control-flow integrity | CET (x86), BTI (arm64) | CET (x86), BTI (arm64) | CFI + BTI (arm64) |
| Strict flex array bounds (`-fstrict-flex-arrays=3`) | yes | yes | yes |
| Hidden symbol visibility | yes | yes | yes + JNI export whitelist |
| LTO (whole-program optimization) | yes | yes | yes |
| **Linker** | | | |
| Full RELRO (read-only GOT) | yes | — | yes |
| Non-executable stack | yes | — | yes |
| Block dlopen (`-z,nodlopen`) | yes | — | — |
| ASLR | OS default | high-entropy | OS default |
| DEP (W^X) | OS default | yes | OS default |
| Fully static binary | yes (musl) | yes | N/A (shared JNI lib) |
| Stripped symbols | yes | yes | yes |
| **Runtime** (`-DCIPHER_HARDEN`) | | | |
| Lock memory (prevent swap) | `mlockall` | — | — |
| Disable core dumps | `RLIMIT_CORE=0` | `SetErrorMode` (WER off) | — |
| Block ptrace / memory inspection | `PR_SET_DUMPABLE=0` | — | — |
| Seccomp-BPF syscall filter | yes (chat loop) | — | — |
| **Key management** | | | |
| Wipe all keys after use (`crypto_wipe`) | yes | yes | yes (native layer) |
| Ephemeral keys only (nothing on disk) | yes | yes | yes |
| **Android-specific** | | | |
| Block screenshots / screen recording | — | — | `FLAG_SECURE` |
| Block overlay windows (tapjacking) | — | — | `setHideOverlayWindows` |
| Custom in-app keyboard (no IME logging) | — | — | yes |
| Wipe UI widgets on background | — | — | yes |
| Kill session on app switch / lock | — | — | yes |
| Exclude from recent apps | — | — | yes |
| Disable backup / data extraction | — | — | yes |
| Strip all log calls in release | — | — | ProGuard/R8 |

## Cryptographic library

The only dependency is [Monocypher](https://monocypher.org/) (vendored as `lib/monocypher.c`):

- Public domain (BSD-2-Clause / CC0 dual-licensed)
- [Audited by Cure53](https://monocypher.org/quality-assurance/audit)
- Constant-time implementations throughout
- Provides: X25519, XChaCha20-Poly1305, BLAKE2b, secure wipe

No OpenSSL, no libsodium, no dynamic linking. The entire cryptographic stack is vendored in `lib/` and links statically.

## FAQ

**Why not just use Signal / WhatsApp / Telegram?**
Those require accounts, phone numbers, and a central server that knows who talks to whom. SimpleCipher has no server, no accounts, and no keys stored to disk. There is no central record of who talked to whom, and no local forensic trace that a conversation ever happened. When the session ends, the keys are gone. Use Signal when you need persistent contacts and key continuity. Use SimpleCipher when leaving no trace matters more.

**Why not just use Tailscale / WireGuard and any chat app?**
Tailscale solves connectivity (NAT traversal), not trust. SimpleCipher adds: ephemeral keys (nothing stored to disk), SAS verification (cryptographic proof of who you're talking to), and forward secrecy (keys wiped after each message). Even if the VPN layer were compromised, SimpleCipher's end-to-end encryption holds. They're complementary — use Tailscale for connectivity, SimpleCipher for trust.

**Is this secure enough for real use?**
The cryptographic primitives (X25519, XChaCha20-Poly1305, BLAKE2b) are industry-standard and provided by [Monocypher](https://monocypher.org/), which has been [audited by Cure53](https://monocypher.org/quality-assurance/audit). The protocol is split into focused modules that are simple enough to audit in an afternoon. That said, this has not been formally audited as a complete system. Use your judgment.

**Why is the binary so small?**
No runtime dependencies. No TLS library, no HTTP stack, no JSON parser, no dynamic linking. The entire program is a handful of focused C modules compiled into a single static binary. Size optimization (`-Os -flto --gc-sections`) removes everything unused.

**Can someone intercept the connection?**
A man-in-the-middle can try, but the commitment scheme and safety code verification prevent it. Both sides commit to their keys before revealing them, then derive a short authentication string (SAS) that must be compared out-of-band (phone call, in person). If the codes match, no MITM is present. If you skip the verification, all bets are off.

**What happens if I lose connection mid-chat?**
The session is gone. Keys are ephemeral and exist only in memory. Reconnect and start a new session — you'll get new keys and a new safety code.

**Can I use this over the internet without a VPN?**
Yes, if one side has a reachable IP (port forwarding, cloud server, etc.). See [Quick start](#quick-start) for options.

**Why C and not Rust / Go / Python?**
C compiles everywhere, links statically, produces tiny binaries, and has zero runtime overhead. The entire protocol fits in a small set of focused modules that can be audited, cross-compiled to 5 targets, and linked directly into Android via JNI. No package manager, no build system complexity, no garbage collector.

## Build from source

### Quick build (native)

```bash
make
```

Or explicitly, if you prefer not to use `make`:

```bash
gcc -O2 -std=c23 -Isrc -Ilib src/*.c src/tui_posix.c src/cli_posix.c lib/monocypher.c -o simplecipher
```

### Cross-compile with CMake presets

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

### Build flags

Binaries are size-optimized: `-Os -flto -ffunction-sections -fdata-sections` with `--gc-sections` for dead code removal. Linux binaries are stripped of build-id, compiler ident, and RELRO segments.

## Tests

```bash
# Run the P2P integration tests
make test

# Run the full local test suite (P2P + build + binary analysis)
bash tests/test_binary.sh
```

### Test coverage

**P2P integration tests** (`tests/test_p2p.c` — 542 tests):
- Crypto primitives: keygen, commitment, DH agreement, SAS derivation, KDF known-answer vectors
- DH ratchet: roundtrip, key rotation, multiple cycles, consecutive sends, long burst (20 messages), post-compromise security proof, simultaneous send, state preservation on failure
- TCP loopback: full handshake + ratcheted message exchange over 127.0.0.1
- Tamper detection, replay rejection, reserved flag rejection
- Forward secrecy chain, chain step aliasing safety (100-iteration feedback loop)
- Edge cases: empty messages, max-length messages (normal + ratchet), over-length rejection
- Input validation: port range, sanitization of non-printable bytes
- Session wipe completeness (all DH ratchet fields zeroed)
- Deterministic session vector: fixed keys produce known SAS `9052-EF29`

**Sanitizers** (CI, blocking):
- AddressSanitizer + UndefinedBehaviorSanitizer on the full test suite (clang-19)
- MemorySanitizer (detects uninitialized memory reads)

**Static analysis** (CI, blocking):
- clang-tidy-19: bugprone, cert, security, clang-analyzer checks

**Fuzzing** (CI smoke + weekly long runs):
- libFuzzer + ASan + UBSan on frame parsing, input sanitization, port validation

**Formal verification** (manual, requires [CBMC](https://github.com/diffblue/cbmc)):
- Bounded model checking on 6 core functions: `frame_open`, `frame_build`, `chain_step`, `ratchet_send`, `ratchet_receive`, `session_init`
- Proves absence of buffer overflow, out-of-bounds access, null pointer dereference, and signed integer overflow for ALL possible inputs (38,279 properties verified)
- Run: `python3 tests/cbmc_harness.py`

**Constant-time verification** (manual, requires x86_64):
- [dudect](https://github.com/oreparaz/dudect) statistical timing analysis on 8 functions: `is_zero32`, `verify_commit`, `domain_hash`, `expand`, `chain_step`, `crypto_x25519`, `frame_build`, `frame_open`
- 7/7 secret-handling functions verified constant-time (~2M measurements each)
- Known-accept: `frame_open` shows timing variance due to Monocypher's intentional MAC-fail fast path (not exploitable — see `test_constant_time.c` for details)
- Run: `gcc -std=c23 -O2 -Isrc -Ilib -Itests tests/test_constant_time.c src/platform.c src/crypto.c src/protocol.c src/ratchet.c src/network.c src/tui.c src/tui_posix.c src/cli.c src/cli_posix.c lib/monocypher.c -lm -o test_ct && taskset -c 0 ./test_ct`

**Platform tests** (run natively on GitHub-hosted runners):

| Binary | Runners |
|--------|---------|
| Linux x86_64 | ubuntu-24.04, ubuntu-22.04 |
| Linux aarch64 | ubuntu-24.04-arm, ubuntu-22.04-arm |
| Windows x86_64 | windows-2025, windows-2022 |
| Windows aarch64 | windows-11-arm |
| Android APK | ubuntu-24.04 (structural validation) |

## Project structure

```
.
├── src/
│   ├── main.c                    # entry point — start reading here
│   ├── platform.h / platform.c   # OS abstraction: sockets, CSPRNG, signals, time
│   ├── crypto.h / crypto.c       # KDF, chain-key ratchet, commitment scheme
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
├── cmake/toolchains/
│   ├── linux-x86_64.cmake        # musl + GCC + mold
│   ├── linux-aarch64.cmake       # musl + GCC + mold
│   ├── win-x86_64.cmake          # llvm-mingw + Clang
│   └── win-aarch64.cmake         # llvm-mingw + Clang
├── android/
│   ├── app/src/main/c/
│   │   ├── CMakeLists.txt        # NDK shared library build
│   │   └── jni_bridge.c          # JNI bridge — links against src/ modules
│   ├── app/src/main/java/.../
│   │   ├── MainActivity.java     # mode selection (Listen / Connect)
│   │   └── ChatActivity.java     # handshake, SAS verification, chat UI
│   └── app/src/main/res/layout/
│       ├── activity_main.xml     # connection setup screen
│       └── activity_chat.xml     # chat interface
├── tests/
│   ├── test_p2p.c                # 273-test P2P integration suite
│   ├── test_binary.sh            # local test runner
│   ├── test_build.sh             # CMake configuration tests
│   ├── test_linux.sh             # ELF binary analysis
│   ├── test_android.sh           # APK structural validation
│   ├── test_windows.ps1          # PE binary analysis (PowerShell)
│   └── test_windows_pe.sh        # PE header checks (cross-platform)
├── .clang-tidy                    # clang-tidy check configuration
└── .github/workflows/
    ├── ci.yml                    # build + test + sanitizers + analysis (12 jobs)
    ├── fuzz.yml                  # weekly long fuzzing runs
    └── release.yml               # build + test + publish on v* tags
```

### Architecture

The protocol is split into focused modules. Each module exposes a header; consumers (`main.c`, `test_p2p.c`, `jni_bridge.c`) include the headers and link against the compiled object files.

```
lib/monocypher.c          (vendored crypto primitives — X25519, XChaCha20-Poly1305, BLAKE2b)
        │
src/platform.h/c          OS abstraction (sockets, CSPRNG, signals, time)
src/crypto.h/c            KDF, chain-key ratchet, commitment scheme
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

## Release

Push a version tag to build on CI, test on all platforms, and publish a GitHub release with SHA256 checksums:

```bash
git tag v0.3.0
git push origin v0.3.0
```

### Verifying release binaries

Every release binary has a [Sigstore](https://www.sigstore.dev/) build provenance attestation. This cryptographically proves the binary was built by this repository's CI — not by a third party. Even if the CI environment were compromised, the attestation is signed by Sigstore's transparency log and cannot be forged.

To verify a downloaded binary:

```bash
gh attestation verify simplecipher-linux-x86_64 --repo robinvanemden/simplecipher
```

This checks that the binary's SHA256 digest matches an attestation signed by GitHub Actions for this repository. If verification fails, do not use the binary.

SHA256 checksums are also provided in `SHA256SUMS.txt` for quick integrity checks, but note that checksums alone do not prove authenticity — they are produced in the same CI job as the binaries.

## License

[MIT](LICENSE) — Monocypher is [BSD-2-Clause / CC0](lib/monocypher.h).
