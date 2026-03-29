# Glossary

> This glossary defines every technical term used across SimpleCipher's documentation. It is organized into three sections by audience: **The Basics** for anyone, **Cryptography** for students and developers, and **Systems Security** for developers and auditors. Each term links to the document where it appears most.

---

## The Basics

Foundational terms for anyone reading SimpleCipher's documentation, no prior experience required.

### Ciphertext

The scrambled, unreadable version of a message after [encryption](#encryption) has been applied. Only someone with the correct [key](#key) can turn it back into [plaintext](#plaintext). *See [PROTOCOL.md](PROTOCOL.md)*

### Encryption

The process of scrambling a message so that only the intended recipient can read it. SimpleCipher uses [XChaCha20-Poly1305](#xchacha20-poly1305) to encrypt every chat message. *See [PROTOCOL.md](PROTOCOL.md)*

### End-to-end encryption (E2EE)

A design where messages are encrypted on the sender's device and decrypted only on the recipient's device. No server, router, or middleman can read them. SimpleCipher is entirely end-to-end: there is no server at all, just a direct connection between two peers. *See [PROTOCOL.md](PROTOCOL.md)*

### Ephemeral

Temporary and not stored. SimpleCipher generates fresh [keys](#key) for every [session](#session), holds them only in RAM, and wipes them on exit. By default, nothing is stored to disk. The optional `keygen` command saves a passphrase-protected identity key file. *See [PROTOCOL.md](PROTOCOL.md#ephemeral)*

### Fingerprint

A short, human-readable summary of a [key](#key), formatted as `XXXX-XXXX-XXXX-XXXX`. SimpleCipher derives fingerprints by hashing the public key with [BLAKE2b](#blake2b), producing 64 bits of entropy. Fingerprints can be shared out-of-band (on paper, via QR code) to verify a peer's identity before connecting. *See [PROTOCOL.md](PROTOCOL.md#fingerprint-verification-optional)*

### Identity key

A persistent [X25519](#x25519) private key stored in a passphrase-protected file, created by `simplecipher keygen`. Unlike [ephemeral](#ephemeral) keys (generated fresh each session), an identity key survives across reboots. When loaded via `--identity`, the identity key **is** the handshake keypair -- the same key used for [Diffie-Hellman](#diffie-hellman-dh) key exchange. Session nonces (random per-session values mixed into the [KDF](#kdf-key-derivation-function)) ensure that each session's derived keys are unique even though the DH shared secret between two fixed identity keys is deterministic. [Forward secrecy](#forward-secrecy) is preserved because the [chain ratchet](#chain-ratchet) and [DH ratchet](#ratchet-dh) still derive and wipe per-message keys.

**Security implications:** Theft of the key file **plus** the passphrase allows impersonation in future sessions (the attacker can pose as you to any peer). Theft of the key file alone (without the passphrase) requires brute-forcing [Argon2id](#argon2id) (100 MB memory, 3 passes). The key file is encrypted with Argon2id + [XChaCha20-Poly1305](#xchacha20-poly1305), requiring both the file (something you have) and the passphrase (something you know). *See [DEPLOYMENT.md](DEPLOYMENT.md)*

### Forward secrecy

A property ensuring that compromising today's [key](#key) cannot decrypt yesterday's messages. SimpleCipher achieves this through a [chain ratchet](#ratchet-symmetricchain) that derives a fresh key for each message and wipes the old one immediately. *See [PROTOCOL.md](PROTOCOL.md#forward-secrecy)*

### IP address

A numeric label that identifies a device on a network, like a street address for your computer. SimpleCipher needs the peer's IP address (or hostname) and [port](#port) to establish a direct connection. *See [WALKTHROUGH.md](WALKTHROUGH.md)*

### Key

A piece of secret data used to lock ([encrypt](#encryption)) and unlock (decrypt) messages. In SimpleCipher, all keys are 32 bytes long, generated from the operating system's random number generator, and wiped from memory after use. *See [PROTOCOL.md](PROTOCOL.md#key-lifecycle)*

### Man-in-the-middle (MITM)

An attack where someone secretly intercepts communication between two people, potentially reading or altering messages. SimpleCipher defeats this with a [commitment scheme](#commitment-scheme) and [SAS](#sas-short-authentication-string) verification. *See [PROTOCOL.md](PROTOCOL.md#2-commitment-scheme-anti-mitm)*

### Plaintext

The original, readable message before [encryption](#encryption). After encrypting, only [ciphertext](#ciphertext) exists on the wire. SimpleCipher never stores plaintext to disk. *See [PROTOCOL.md](PROTOCOL.md)*

### Port

A number (1-65535) that identifies a specific service on a device, like an apartment number within a building. When listening for connections, SimpleCipher binds to a port; when connecting, you specify the peer's port. *See [WALKTHROUGH.md](WALKTHROUGH.md)*

### Session

A single conversation between two peers, from connection to disconnection. Each session generates its own [ephemeral](#ephemeral) keys. There is no state carried between sessions: once you disconnect, the keys are gone forever. *See [PROTOCOL.md](PROTOCOL.md#what-it-does-not-provide)*

---

## Cryptography

Terms for readers who want to understand how SimpleCipher's protocol works under the hood.

### AEAD (Authenticated Encryption with Associated Data)

Authenticated Encryption with Associated Data. [Encryption](#encryption) that also proves the message was not tampered with. SimpleCipher uses [XChaCha20-Poly1305](#xchacha20-poly1305) as its AEAD cipher. The "associated data" (the sequence number) is authenticated but not encrypted: visible, yet tamper-proof. *See [PROTOCOL.md](PROTOCOL.md#aead)*

### Asymmetric encryption

A system using two mathematically related keys: a public key (shared openly) and a private key (kept secret). SimpleCipher uses asymmetric cryptography for [key exchange](#x25519) only; actual messages are encrypted with a shared [symmetric](#symmetric-encryption) key derived from the exchange. *See [PROTOCOL.md](PROTOCOL.md#1-key-exchange)*

### BLAKE2b

A fast, secure hash function that takes any input and produces a fixed 32-byte output. The same input always gives the same output, but the process cannot be reversed. SimpleCipher uses BLAKE2b for [commitments](#commitment-scheme), [key derivation](#kdf-key-derivation-function), [fingerprints](#fingerprint), and domain separation, all via [Monocypher](#monocypher). *See [PROTOCOL.md](PROTOCOL.md#blake2b)*

### CDH

Computational Diffie-Hellman. The mathematical assumption underlying [X25519](#x25519): given two public values, it is computationally infeasible to derive the shared secret without knowing at least one private key. SimpleCipher's entire key exchange security rests on this hardness assumption. *See [PROTOCOL.md](PROTOCOL.md#1-key-exchange)*

### Chain ratchet

See [Ratchet (symmetric/chain)](#ratchet-symmetricchain).

### Commitment scheme

A two-phase protocol: first *commit* (send `H(pub || nonce)` — a [hash](#blake2b) binding the public key to a fresh random nonce), then *reveal* (send the actual public key). The receiver checks that the hash of the revealed key and previously received nonce matches the commitment. In SimpleCipher, both sides commit to their public keys before revealing them. This prevents a [man-in-the-middle](#man-in-the-middle-mitm) from seeing one key and crafting a fake key that produces a matching [SAS](#sas-short-authentication-string) code. *See [PROTOCOL.md](PROTOCOL.md#commitment-scheme)*

### Cover traffic

Fake messages sent on a random schedule to mask when real messages are being typed. SimpleCipher uses a queue-on-tick design: real messages are queued and sent on the next cover tick, replacing the cover payload. Inter-frame intervals follow a clamped exponential distribution (mean 500 ms, range [50, 1500] ms) that mimics natural Poisson traffic, making the stream hard to fingerprint. All outgoing frames follow the same timing distribution, defeating statistical timing analysis. Enabled automatically over [SOCKS5](#socks5)/[Tor](#tor). *See [PROTOCOL.md](PROTOCOL.md#6-wire-padding-dpi-resistance)*

### DH ratchet

See [Ratchet (DH)](#ratchet-dh).

### Diffie-Hellman (DH)

A method that lets two parties compute a shared secret over a public channel without ever transmitting the secret itself. Each side generates a keypair, they exchange public keys, and the math produces the same shared value on both ends. SimpleCipher uses [X25519](#x25519), an elliptic-curve variant of DH. *See [PROTOCOL.md](PROTOCOL.md#1-key-exchange)*

### Domain separation

A technique that ensures hashing the same data for different purposes produces unrelated outputs. SimpleCipher prefixes each [BLAKE2b](#blake2b) hash with a unique label (e.g., `"cipher commit v3"`, `"cipher x25519 sas root v1"`), so values derived for one purpose cannot be confused with or substituted for another. *See [PROTOCOL.md](PROTOCOL.md)*

### Double ratchet

The combination of a [symmetric chain ratchet](#ratchet-symmetricchain) ([forward secrecy](#forward-secrecy)) and a [DH ratchet](#ratchet-dh) ([post-compromise security](#post-compromise-security-pcs)). This is the same architecture that Signal uses. SimpleCipher implements both ratchets across `crypto.c` and `ratchet.c`. *See [PROTOCOL.md](PROTOCOL.md#4-encrypted-messaging-with-forward-secrecy-and-post-compromise-security)*

### KDF (Key Derivation Function)

Key Derivation Function. Takes one secret and derives multiple independent [keys](#key) from it. SimpleCipher uses [BLAKE2b](#blake2b) as its KDF: the shared secret goes in, and separate keys for sending, receiving, and the [SAS](#sas-short-authentication-string) come out. Knowing one derived key reveals nothing about the others. *See [PROTOCOL.md](PROTOCOL.md#kdf)*

### MAC (Message Authentication Code)

Message Authentication Code. A short tag appended to each message that proves it was not tampered with. In SimpleCipher, Poly1305 computes a 16-byte MAC over each frame; the receiver recomputes it and compares. If they differ, the frame is rejected. *See [PROTOCOL.md](PROTOCOL.md#mac)*

### Monocypher

The sole cryptographic library used by SimpleCipher, vendored as `lib/monocypher.c`. It provides [X25519](#x25519), [XChaCha20-Poly1305](#xchacha20-poly1305), [BLAKE2b](#blake2b), and secure memory wipe. Dual-licensed BSD-2-Clause or CC0-1.0, audited by Cure53, constant-time throughout. *See [PROTOCOL.md](PROTOCOL.md#cryptographic-library)*

### Nonce

"Number used once." A value that must never repeat with the same [key](#key). In SimpleCipher, each message uses a different key (from the [chain ratchet](#ratchet-symmetricchain)), so the nonce is simply the sequence number. The (key, nonce) pair is always unique, which is what the [AEAD](#aead-authenticated-encryption-with-associated-data) cipher requires. *See [PROTOCOL.md](PROTOCOL.md#nonce)*

### Post-compromise security (PCS)

A property ensuring that stealing a [key](#key) now does not let an attacker read future messages. The [DH ratchet](#ratchet-dh) mixes fresh random [X25519](#x25519) entropy on each conversation direction switch, creating a new chain the attacker cannot predict even if they stole the old chain key. *See [PROTOCOL.md](PROTOCOL.md#post-compromise-security)*

### PRF

Pseudo-Random Function. A deterministic function whose output is indistinguishable from random to anyone who does not know the key. SimpleCipher uses keyed [BLAKE2b](#blake2b) as a PRF for [key derivation](#kdf-key-derivation-function) and the [chain ratchet](#ratchet-symmetricchain) step. *See [PROTOCOL.md](PROTOCOL.md)*

### Ratchet (DH)

A mechanism that injects fresh randomness into the key hierarchy. When the conversation direction switches (one side was receiving, now they send), a fresh [X25519](#x25519) keypair is generated, a new shared secret is computed with the peer's latest public key, and a new sending chain is derived from it. In SimpleCipher, this computation is pre-staged eagerly (at session init and after each receive) so that sends have no timing asymmetry. This provides [post-compromise security](#post-compromise-security-pcs). *See [PROTOCOL.md](PROTOCOL.md#4-encrypted-messaging-with-forward-secrecy-and-post-compromise-security)*

### Safety code

See [SAS (Short Authentication String)](#sas-short-authentication-string).

### Ratchet (symmetric/chain)

A one-way key advancement mechanism. Each message derives a fresh encryption [key](#key) from the current chain key, then the chain steps forward and the old key is wiped. This provides per-message [forward secrecy](#forward-secrecy): compromising one message key reveals nothing about any other. *See [PROTOCOL.md](PROTOCOL.md#4-encrypted-messaging-with-forward-secrecy-and-post-compromise-security)*

### SAS (Short Authentication String)

Short Authentication String. A short code (formatted as `XXXX-XXXX`) derived from the shared secret and displayed on both screens. Users compare it out-of-band (phone call, video call) to confirm no [man-in-the-middle](#man-in-the-middle-mitm) is present. The 32-bit code space is sufficient because the [commitment scheme](#commitment-scheme) prevents brute-force search. *See [PROTOCOL.md](PROTOCOL.md#sas)*

### Symmetric encryption

[Encryption](#encryption) where both sides share the same secret [key](#key). Faster than [asymmetric encryption](#asymmetric-encryption), but requires a way to agree on the key first. SimpleCipher uses [X25519](#x25519) (asymmetric) to agree on a key, then [XChaCha20-Poly1305](#xchacha20-poly1305) (symmetric) for all message encryption. *See [PROTOCOL.md](PROTOCOL.md)*

### X25519

An elliptic-curve [Diffie-Hellman](#diffie-hellman-dh) key exchange algorithm built on Curve25519. Two people each generate a random keypair, exchange public keys, and both compute the same 32-byte shared secret without ever transmitting it. SimpleCipher uses X25519 for the initial handshake and for every [DH ratchet](#ratchet-dh) step. *See [PROTOCOL.md](PROTOCOL.md#x25519)*

### XChaCha20-Poly1305

An [AEAD](#aead-authenticated-encryption-with-associated-data) cipher that combines XChaCha20 (stream cipher for confidentiality) with Poly1305 ([MAC](#mac-message-authentication-code) for integrity). It encrypts a message so only the [key](#key) holder can read it, and produces a 16-byte tag that detects any tampering. SimpleCipher uses it for all message encryption via [Monocypher](#monocypher). *See [PROTOCOL.md](PROTOCOL.md#xchacha20-poly1305)*

---

## Systems Security

Terms for developers and auditors reviewing SimpleCipher's hardening, build, and deployment.

### Argon2id

A password hashing algorithm designed to be slow and memory-intensive, making brute-force attacks expensive. SimpleCipher uses Argon2id (100 MB memory, 3 passes) to derive an encryption key from the passphrase that protects an [identity key](#identity-key) file. Even a weak passphrase takes significant time and memory to crack. Part of [Monocypher](#monocypher). *See [HARDENING.md](HARDENING.md)*

### APK (Android Package)

Android Package Kit. The file format used to distribute Android applications. SimpleCipher's Android build produces a debug APK via Gradle; release APKs are signed with a keystore for distribution. *See [ANDROID.md](ANDROID.md)*

### ASLR (Address Space Layout Randomization)

Address Space Layout Randomization. An OS feature that randomizes where a program's code and data are placed in memory, making it harder for an attacker to exploit memory corruption bugs. SimpleCipher is compiled as a [PIE](#pie-position-independent-executable) binary where toolchain support is available (Windows, native builds); static musl-linked Linux binaries currently lack PIE (see [HARDENING.md](HARDENING.md) for status). *See [HARDENING.md](HARDENING.md)*

### BTI (Branch Target Identification)

Branch Target Identification. An ARM64 hardware feature that restricts where indirect branches can land, preventing attackers from diverting execution to arbitrary code. SimpleCipher enables BTI on AArch64 builds via compiler flags. *See [HARDENING.md](HARDENING.md)*

### Capsicum

A capability-based security framework on FreeBSD. After entering capability mode (`cap_enter()`), a process can only use file descriptors it already holds and cannot open new files, sockets, or connections. SimpleCipher uses Capsicum on FreeBSD as its syscall sandbox. *See [HARDENING.md](HARDENING.md)*

### CET (Control-flow Enforcement Technology)

Control-flow Enforcement Technology. An Intel hardware feature that uses a shadow stack to detect return address tampering. SimpleCipher enables CET on x86_64 builds where supported. *See [HARDENING.md](HARDENING.md)*

### CFI (Control-Flow Integrity)

Control Flow Integrity. A compiler technique that restricts indirect calls and jumps to valid targets, preventing attackers from hijacking execution. SimpleCipher enables CFI through compiler flags in hardened builds. *See [HARDENING.md](HARDENING.md)*

### Constant-time

A coding discipline where operations take the same amount of time regardless of the input values. This prevents attackers from measuring execution time to infer secret data (a "timing side-channel"). SimpleCipher's `ct_compare` and `is_zero32` functions use this technique, and [Monocypher](#monocypher) is constant-time throughout. *See [HARDENING.md](HARDENING.md)*

### CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)

Cryptographically Secure Pseudo-Random Number Generator. A source of random bytes suitable for generating [keys](#key) and [nonces](#nonce). SimpleCipher uses the operating system's CSPRNG (`getrandom` on Linux, `getentropy` on BSD, `BCryptGenRandom` on Windows) and never implements its own. *See [PROTOCOL.md](PROTOCOL.md)*

### DEP (Data Execution Prevention)

Data Execution Prevention. An OS/hardware feature that marks memory pages as either writable or executable, but never both (also known as [W^X](#wx-write-xor-execute)). Prevents injected data from being executed as code. SimpleCipher benefits from DEP on all supported platforms. *See [HARDENING.md](HARDENING.md)*

### DPI (Deep Packet Inspection)

Deep Packet Inspection. A technique where network middleboxes examine packet contents to identify or block specific protocols. SimpleCipher's wire format uses random-length padding to vary message sizes (513-768 bytes), raising the cost of naive fixed-size pattern matching. The fixed 512-byte inner frame and cleartext 8-byte sequence number are distinguishing features for sophisticated observers — see [THREAT_MODEL.md](THREAT_MODEL.md) for limitations. *See [PROTOCOL.md](PROTOCOL.md#6-wire-padding-dpi-resistance)*

### IME (Input Method Editor)

Input Method Editor. Software that intercepts keyboard input to compose characters (common for CJK languages, but also predictive text on mobile). IMEs can log keystrokes. SimpleCipher's Android build uses `android:inputType="textVisiblePassword"` to suppress IME suggestions and prevent sensitive text from entering the IME's prediction dictionary. *See [ANDROID.md](ANDROID.md)*

### JNI (Java Native Interface)

Java Native Interface. The bridge between Java/Kotlin code running on Android's JVM and native C code. SimpleCipher's Android app uses JNI to call the same C protocol library used by the desktop builds, keeping all cryptographic operations in native code where `crypto_wipe()` works reliably. *See [ANDROID.md](ANDROID.md)*

### LTO (Link-Time Optimization)

Link-Time Optimization. A compiler technique that optimizes across all source files at link time rather than one file at a time, enabling better dead-code elimination and inlining. SimpleCipher uses `-flto` for smaller, faster binaries. *See [BUILDING.md](BUILDING.md)*

### musl

A lightweight, static-friendly C standard library. SimpleCipher's Linux builds link against musl instead of glibc, producing fully static binaries with zero runtime dependencies. This means the binary runs on any Linux kernel without needing shared libraries. *See [BUILDING.md](BUILDING.md)*

### NDK (Native Development Kit)

Native Development Kit. Android's toolchain for compiling C/C++ code to run on Android devices. SimpleCipher uses the NDK to cross-compile its C protocol library for ARM64, ARM, x86_64, and x86 Android targets. *See [ANDROID.md](ANDROID.md)*

### PIE (Position-Independent Executable)

Position-Independent Executable. A binary compiled so it can be loaded at any memory address, enabling [ASLR](#aslr-address-space-layout-randomization). SimpleCipher uses PIE where toolchain support is available; static musl-linked Linux binaries currently use `-static` without `-static-pie` (pending musl toolchain upgrade). *See [HARDENING.md](HARDENING.md)*

### pledge / unveil

OpenBSD system calls that restrict what a process can do. `pledge` limits available system calls to a named set (e.g., `"stdio"`), and `unveil` restricts filesystem visibility. After SimpleCipher's handshake, it pledges `"stdio"` only, blocking all file and network operations beyond the existing connection. *See [HARDENING.md](HARDENING.md)*

### RELRO (Relocation Read-Only)

Relocation Read-Only. A linker hardening feature that marks the Global Offset Table (GOT) as read-only after startup, preventing attackers from overwriting function pointers. SimpleCipher uses full RELRO (`-Wl,-z,relro,-z,now`). *See [HARDENING.md](HARDENING.md)*

### Sanitizer

A compiler instrumentation tool that detects bugs at runtime: AddressSanitizer finds memory errors, UndefinedBehaviorSanitizer catches undefined behavior, and MemorySanitizer detects uninitialized reads. SimpleCipher's test suite runs under sanitizers in CI to catch bugs before release. *See [BUILDING.md](BUILDING.md)*

### seccomp (Secure Computing Mode)

Secure Computing Mode. A Linux kernel feature that restricts which system calls a process can make. SimpleCipher installs a seccomp-BPF filter after the handshake, allowing only I/O, memory management, and exit. Blocked calls include `open`, `connect`, `execve`, and `ptrace`. *See [HARDENING.md](HARDENING.md)*

### SOCKS5

A proxy protocol that routes TCP connections through an intermediary. SimpleCipher supports SOCKS5 via `--socks5 host:port`, enabling connections through [Tor](#tor) to hide IP addresses from the peer and the network. Cover traffic is enabled automatically when SOCKS5 is active. *See [WALKTHROUGH.md](WALKTHROUGH.md)*

### Stack canary

A random value placed on the stack before a function's return address. If a buffer overflow overwrites the canary, the program detects the corruption and aborts instead of executing attacker-controlled code. SimpleCipher is compiled with `-fstack-protector-strong`. *See [HARDENING.md](HARDENING.md)*

### Tor

The Onion Router. An anonymity network that routes traffic through multiple relays to hide the user's IP address. SimpleCipher can connect through Tor via [SOCKS5](#socks5) (`--socks5 127.0.0.1:9050`), and listeners can expose an onion service so neither peer learns the other's real IP. *See [WALKTHROUGH.md](WALKTHROUGH.md)*

### W^X (Write XOR Execute)

Write XOR Execute. A memory protection policy where pages are either writable or executable, never both. This prevents injected data from being executed as code (also known as [DEP](#dep-data-execution-prevention)). SimpleCipher benefits from W^X enforcement on all supported platforms. *See [HARDENING.md](HARDENING.md)*
