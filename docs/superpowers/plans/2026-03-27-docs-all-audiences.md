# Documentation for All Audiences — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a glossary, formal security analysis, beginner-friendly intros, and inline glossary links across all docs so that noobs, students, developers, and PhD cryptographers can each find what they need.

**Architecture:** Two new files (GLOSSARY.md, FORMAL_ANALYSIS.md) provide the anchors. Existing docs get light edits: intro paragraphs for the intimidating ones, inline links on first use of every technical term, and a "New to cryptography?" callout in the README. No content is rewritten — we add access layers.

**Tech Stack:** Markdown only. No build tools, no code changes.

**Spec:** `docs/superpowers/specs/2026-03-27-docs-all-audiences-design.md`

---

## Task 1: Create `docs/GLOSSARY.md`

**Files:**
- Create: `docs/GLOSSARY.md`

This is the foundation — all other tasks link to it. Write the complete glossary with ~50 terms across three sections. Every definition follows the pattern: plain-English first → precise meaning → why SimpleCipher uses it → "See also" link.

- [ ] **Step 1: Write the full glossary file**

Create `docs/GLOSSARY.md` with this exact content structure. Each term gets an `###` heading (which creates the anchor targets other docs will link to). Terms within each section are alphabetical.

```markdown
# Glossary

> Look up any technical term used in SimpleCipher's documentation.
> Terms are grouped by topic. If you're brand new, start with **The Basics**.

---

## The Basics

Terms anyone needs to understand what SimpleCipher does.

### Ciphertext

The scrambled version of a message after encryption. It looks like random garbage to anyone who doesn't have the key. The opposite of [plaintext](#plaintext). — *See [PROTOCOL.md](PROTOCOL.md)*

### Encryption

Scrambling a message so that only the intended recipient can read it. SimpleCipher encrypts every message before it leaves your computer. — *See [PROTOCOL.md](PROTOCOL.md)*

### End-to-end encryption (E2EE)

Encryption where only the two people chatting can read messages — not the network, not a server, not even SimpleCipher itself. The keys never leave the two devices. — *See [PROTOCOL.md](PROTOCOL.md)*

### Ephemeral

Temporary — exists only during a single session and is destroyed afterward. SimpleCipher's keys are ephemeral: they live in memory while you chat and are wiped when you close the program. Nothing is ever written to disk. — *See [DESIGN_BOUNDARIES.md](DESIGN_BOUNDARIES.md)*

### Fingerprint

A short code (like `58A4-0798-FE8A-4026`) that uniquely identifies a public key. You can share your fingerprint before a session so your peer can verify they're connecting to you, not an impersonator. — *See [ANDROID.md](ANDROID.md)*

### Forward secrecy

A property that protects past messages even if a key is compromised later. SimpleCipher achieves this by deriving a new key for every single message and immediately wiping the old one. Even if an attacker steals your current key, they cannot decrypt anything you sent before. — *See [PROTOCOL.md](PROTOCOL.md)*

### Hash

A one-way mathematical function that turns any input into a fixed-size fingerprint (like a 32-byte string). You can't reverse it to get the original input back. SimpleCipher uses [BLAKE2b](#blake2b) for hashing. — *See [PROTOCOL.md](PROTOCOL.md)*

### IP address

A number that identifies your computer on a network (like `192.168.1.42`). When you connect to a peer, you need their IP address. SimpleCipher does not hide your IP — for anonymity, use [Tor](#tor). — *See [DEPLOYMENT.md](DEPLOYMENT.md)*

### Key

A secret piece of data used to encrypt or decrypt messages. Think of it as the combination to a lock. SimpleCipher uses 32-byte (256-bit) keys. — *See [PROTOCOL.md](PROTOCOL.md)*

### MITM (Man-in-the-Middle attack)

An attack where someone secretly sits between you and your peer, reading or altering messages. SimpleCipher's [SAS](#sas) verification defeats this: if the safety codes match, no one is in the middle. — *See [PROTOCOL.md](PROTOCOL.md)*

### Plaintext

The original, unencrypted message. The opposite of [ciphertext](#ciphertext). SimpleCipher encrypts plaintext before sending it and decrypts ciphertext when receiving it. — *See [PROTOCOL.md](PROTOCOL.md)*

### Port

A number (like `7777`) that identifies a specific service on a computer. When SimpleCipher listens for connections, it opens a port. The default is 7777, but you can choose any available port. — *See [README](../README.md)*

### Session

A single conversation between two people. Each session generates fresh keys, and when it ends, those keys are destroyed. There is no way to "resume" a session — you start a new one each time. — *See [PROTOCOL.md](PROTOCOL.md)*

---

## Cryptography

Terms used in the protocol and security documentation. If you're learning, the [Walkthrough](WALKTHROUGH.md) explains how these pieces fit together.

### AEAD (Authenticated Encryption with Associated Data)

An encryption method that provides both confidentiality (nobody can read the message) and integrity (nobody can tamper with it without being detected). SimpleCipher uses [XChaCha20-Poly1305](#xchacha20-poly1305) as its AEAD. The "associated data" is the message sequence number, which is authenticated but not encrypted. — *See [PROTOCOL.md](PROTOCOL.md)*

### Asymmetric encryption

Encryption using a pair of keys: a public key (shared openly) and a private key (kept secret). Anyone can encrypt a message with the public key, but only the private key can decrypt it. SimpleCipher uses [X25519](#x25519) for the asymmetric part of the key exchange. — *See [PROTOCOL.md](PROTOCOL.md)*

### BLAKE2b

A fast, secure hash function used by SimpleCipher for key derivation and domain separation. It is part of the [Monocypher](#monocypher) library. Think of it as the engine that turns shared secrets into usable keys. — *See [PROTOCOL.md](PROTOCOL.md)*

### CDH (Computational Diffie-Hellman assumption)

The mathematical assumption that it's hard to compute the shared secret from two public keys without knowing either private key. This is the foundation of [X25519](#x25519) security. If CDH is broken (e.g., by a sufficiently powerful quantum computer), X25519 is broken too. — *See [FORMAL_ANALYSIS.md](FORMAL_ANALYSIS.md)*

### Chain ratchet

See [Ratchet (symmetric / chain)](#ratchet-symmetric--chain).

### Commitment scheme

A two-step process where you first "commit" to a value (by publishing its hash) and then "reveal" the actual value. SimpleCipher uses this during the handshake: both sides commit to their public keys before revealing them. This prevents a [MITM](#mitm-man-in-the-middle-attack) attacker from crafting a key that makes the [SAS](#sas) codes match. — *See [PROTOCOL.md](PROTOCOL.md)*

### Cover traffic

Fake encrypted messages sent at random intervals to make it harder for a network observer to tell when you're actually typing. Without cover traffic, someone watching the network could see your message timing patterns even though they can't read the content. SimpleCipher sends cover traffic automatically when enabled with `--cover-traffic`. — *See [DEPLOYMENT.md](DEPLOYMENT.md)*

### DH (Diffie-Hellman)

A method that lets two people create a shared secret over an insecure channel. Each person generates a key pair, they exchange public keys, and both independently compute the same shared secret. An eavesdropper who sees only the public keys cannot compute the secret. SimpleCipher uses the [X25519](#x25519) variant. — *See [PROTOCOL.md](PROTOCOL.md)*

### DH ratchet

See [Ratchet (DH)](#ratchet-dh).

### Domain separation

Using a unique label (like `"cipher commit v3"`) when hashing or deriving keys, so that outputs from different contexts can never collide. For example, the hash used for commitments and the hash used for fingerprints use different labels, even though they use the same [BLAKE2b](#blake2b) function. — *See [PROTOCOL.md](PROTOCOL.md)*

### Double ratchet

The combination of a [symmetric (chain) ratchet](#ratchet-symmetric--chain) and a [DH ratchet](#ratchet-dh). The chain ratchet provides [forward secrecy](#forward-secrecy) per message. The DH ratchet provides [post-compromise security](#post-compromise-security) per direction switch. Together, they give SimpleCipher both properties. Inspired by the Signal protocol. — *See [WALKTHROUGH.md](WALKTHROUGH.md)*

### KDF (Key Derivation Function)

A function that takes a secret and produces one or more cryptographic keys from it. SimpleCipher uses [BLAKE2b](#blake2b) in keyed mode as its KDF. For example, the initial shared secret is expanded into a SAS key, a root key, and two chain keys. — *See [PROTOCOL.md](PROTOCOL.md)*

### MAC (Message Authentication Code)

A short tag attached to each message that proves it hasn't been tampered with. If even one bit of the message changes, the MAC won't match, and SimpleCipher rejects the frame. SimpleCipher uses [Poly1305](#xchacha20-poly1305) (16-byte MAC). — *See [PROTOCOL.md](PROTOCOL.md)*

### Monocypher

The cryptographic library SimpleCipher uses for all low-level crypto operations ([X25519](#x25519), [XChaCha20-Poly1305](#xchacha20-poly1305), [BLAKE2b](#blake2b)). It's a small, audited, public-domain C library vendored in `lib/monocypher.c`. SimpleCipher never modifies it. — *See [PROTOCOL.md](PROTOCOL.md)*

### Nonce (number used once)

A unique value used exactly once with each encryption operation to ensure that encrypting the same message twice produces different ciphertext. SimpleCipher derives the nonce from the message sequence number, guaranteeing uniqueness. If a nonce were ever reused with the same key, security would be destroyed. — *See [PROTOCOL.md](PROTOCOL.md)*

### Post-compromise security (PCS)

The ability to recover security after a key compromise. If an attacker somehow learns your current key, the [DH ratchet](#ratchet-dh) introduces fresh randomness on the next direction switch, making the new keys independent of the compromised ones. Recovery takes one round-trip (you send, they reply). — *See [PROTOCOL.md](PROTOCOL.md)*

### PRF (Pseudorandom Function)

A keyed function whose output is indistinguishable from random to anyone who doesn't know the key. SimpleCipher treats [BLAKE2b](#blake2b) in keyed mode as a PRF for key derivation. — *See [FORMAL_ANALYSIS.md](FORMAL_ANALYSIS.md)*

### Ratchet (DH)

A mechanism that injects fresh randomness by performing a new [Diffie-Hellman](#dh-diffie-hellman) exchange. SimpleCipher performs a DH ratchet step each time the conversation direction switches (you were receiving and now you send, or vice versa). This provides [post-compromise security](#post-compromise-security). — *See [WALKTHROUGH.md](WALKTHROUGH.md)*

### Ratchet (symmetric / chain)

A one-way key update: the current chain key derives a message key and a new chain key, then the old chain key is wiped. This means each message uses a unique key, and old message keys can never be recovered. This is what provides [forward secrecy](#forward-secrecy). — *See [WALKTHROUGH.md](WALKTHROUGH.md)*

### SAS (Short Authentication String)

A short code (like `9052-EF29`) that both peers see on screen after connecting. By comparing this code out-of-band (e.g., over a phone call), you verify that no [MITM](#mitm-man-in-the-middle-attack) attacker is between you. If the codes match, the connection is authentic. — *See [PROTOCOL.md](PROTOCOL.md)*

### Symmetric encryption

Encryption where both sides use the same key. Faster than [asymmetric encryption](#asymmetric-encryption), but both parties must agree on the key first. SimpleCipher uses asymmetric crypto ([X25519](#x25519)) to agree on a key, then symmetric crypto ([XChaCha20-Poly1305](#xchacha20-poly1305)) for the actual messages. — *See [PROTOCOL.md](PROTOCOL.md)*

### X25519

An elliptic-curve [Diffie-Hellman](#dh-diffie-hellman) algorithm for key agreement. Two parties exchange 32-byte public keys and each independently computes the same 32-byte shared secret. It's fast, constant-time, and widely used (Signal, WireGuard, SSH). Part of [Monocypher](#monocypher). — *See [PROTOCOL.md](PROTOCOL.md)*

### XChaCha20-Poly1305

An [AEAD](#aead-authenticated-encryption-with-associated-data) cipher that encrypts data (ChaCha20 stream cipher) and authenticates it (Poly1305 [MAC](#mac-message-authentication-code)) in one operation. The "X" means extended nonce (24 bytes), which makes accidental nonce reuse astronomically unlikely. Part of [Monocypher](#monocypher). — *See [PROTOCOL.md](PROTOCOL.md)*

---

## Systems Security

Terms used in the hardening, threat model, and deployment documentation.

### APK (Android Package)

The file format for Android apps. SimpleCipher provides pre-built APKs for download, or you can build from source. — *See [ANDROID.md](ANDROID.md)*

### ASLR (Address Space Layout Randomization)

A defense that loads programs at random memory addresses each time they run. This makes it much harder for an attacker to exploit a memory bug because they can't predict where code or data will be in memory. Enabled by default on all SimpleCipher platforms. — *See [HARDENING.md](HARDENING.md)*

### BTI (Branch Target Identification)

An ARM processor feature that restricts which instructions can be targets of indirect branches (jumps). This blocks a class of attacks where an attacker redirects program execution to arbitrary code. Enabled on aarch64 SimpleCipher builds. — *See [HARDENING.md](HARDENING.md)*

### Capsicum

A capability-based security framework on FreeBSD. Once SimpleCipher enters Capsicum mode, the process can only use file descriptors it already has open — it cannot open new files, make new network connections, or access the filesystem. — *See [HARDENING.md](HARDENING.md)*

### CET (Control-flow Enforcement Technology)

An Intel/AMD processor feature that prevents attackers from hijacking program control flow. It uses a hardware-protected shadow stack and indirect branch tracking. Enabled on x86_64 SimpleCipher builds. — *See [HARDENING.md](HARDENING.md)*

### CFI (Control-Flow Integrity)

A broad category of defenses that ensure a program only executes valid code paths. [CET](#cet-control-flow-enforcement-technology) and [BTI](#bti-branch-target-identification) are hardware implementations of CFI for x86_64 and ARM respectively. — *See [HARDENING.md](HARDENING.md)*

### Constant-time

Code that takes the same amount of time regardless of the secret data it processes. If encryption took longer for certain keys, an attacker could measure the timing and deduce the key. SimpleCipher's secret-handling functions are verified constant-time using two independent tools (Timecop/Valgrind and dudect). — *See [HARDENING.md](HARDENING.md)*

### CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)

A random number generator safe for cryptographic use — its output is indistinguishable from true randomness. SimpleCipher uses the OS-provided CSPRNG (`getrandom` on Linux, `BCryptGenRandom` on Windows) for all key generation and random padding. — *See [PROTOCOL.md](PROTOCOL.md)*

### DEP (Data Execution Prevention)

A security feature that marks memory regions as either writable or executable, but never both. This prevents an attacker from injecting code into data areas and running it. Also called [W^X](#wx-write-xor-execute). — *See [HARDENING.md](HARDENING.md)*

### DPI (Deep Packet Inspection)

Network surveillance that examines the content and patterns of network traffic, not just addresses and ports. SimpleCipher defeats DPI fingerprinting by adding random-length padding to all frames and handshake messages, making traffic look like random noise. — *See [PROTOCOL.md](PROTOCOL.md)*

### IME (Input Method Editor)

The software keyboard on mobile devices. Most IMEs log keystrokes (for autocomplete, prediction, etc.), which could leak your messages. SimpleCipher's Android app uses a custom in-app keyboard that bypasses the IME entirely. — *See [ANDROID.md](ANDROID.md)*

### JNI (Java Native Interface)

The bridge between Java (Android UI) and C (SimpleCipher's crypto/protocol code). The Android app's UI is Java; all security-critical logic runs in native C via JNI. — *See [ANDROID.md](ANDROID.md)*

### LTO (Link-Time Optimization)

A compiler technique that optimizes the entire program at link time rather than file by file. This produces smaller, faster binaries. SimpleCipher uses LTO in all release builds. — *See [BUILDING.md](BUILDING.md)*

### musl

A lightweight C standard library used for building fully static Linux binaries. Unlike glibc, musl supports static linking cleanly, meaning SimpleCipher Linux binaries have zero runtime dependencies. — *See [BUILDING.md](BUILDING.md)*

### NDK (Native Development Kit)

Android's toolchain for compiling C/C++ code that runs on Android devices. SimpleCipher uses NDK r28 to cross-compile its C protocol code for ARM and x86 Android CPUs. — *See [ANDROID.md](ANDROID.md)*

### PIE (Position Independent Executable)

A binary compiled so it can be loaded at any memory address, which is required for [ASLR](#aslr-address-space-layout-randomization) to work. Note: SimpleCipher's static musl binaries currently lack PIE due to a musl toolchain limitation. — *See [THREAT_MODEL.md](THREAT_MODEL.md)*

### pledge / unveil

OpenBSD security mechanisms. `pledge` restricts which system calls a program can make (SimpleCipher pledges only `"stdio"`). `unveil` restricts filesystem access (SimpleCipher calls `unveil(NULL, NULL)` to block all filesystem access). — *See [HARDENING.md](HARDENING.md)*

### RELRO (Relocation Read-Only)

A linker hardening that makes parts of the program's memory read-only after startup. Full RELRO (used by SimpleCipher) protects the Global Offset Table from being overwritten by an attacker. — *See [HARDENING.md](HARDENING.md)*

### Sanitizer

A development tool that instruments code to detect bugs at runtime. SimpleCipher's CI uses three sanitizers: AddressSanitizer (ASan) catches memory errors, UndefinedBehaviorSanitizer (UBSan) catches undefined C behavior, and MemorySanitizer (MSan) catches uninitialized memory reads. — *See [HARDENING.md](HARDENING.md)*

### Seccomp (Secure Computing Mode)

A Linux kernel feature that restricts which system calls a process can make. SimpleCipher uses a two-phase seccomp-BPF filter: phase 1 (after TCP connect) blocks new sockets, phase 2 (after handshake) tightens to the minimum needed for encrypted chat. — *See [HARDENING.md](HARDENING.md)*

### SOCKS5

A network proxy protocol. SimpleCipher can route connections through a SOCKS5 proxy (like [Tor](#tor)) to hide your IP address. The proxy sees that you're connecting *somewhere* but cannot read the encrypted traffic. — *See [DEPLOYMENT.md](DEPLOYMENT.md)*

### Stack canary

A random value placed between a function's local variables and its return address. If a buffer overflow corrupts the canary, the program detects it and aborts before the attacker can hijack execution. Enabled via `-fstack-protector-strong`. — *See [HARDENING.md](HARDENING.md)*

### Tor

A network that routes your traffic through multiple relays to hide your IP address. SimpleCipher can connect through Tor via [SOCKS5](#socks5) (using `--socks5 127.0.0.1:9050` or Orbot on Android). Tor hides *who* is communicating; SimpleCipher's encryption hides *what* is communicated. — *See [DEPLOYMENT.md](DEPLOYMENT.md)*

### W^X (Write XOR Execute)

A memory protection policy: memory pages can be writable or executable, but never both at the same time. This prevents an attacker from writing code into memory and then executing it. Same concept as [DEP](#dep-data-execution-prevention). — *See [HARDENING.md](HARDENING.md)*
```

- [ ] **Step 2: Verify all anchor targets are correct**

Run this command to extract all `###` headings and verify they match the expected anchor format (lowercase, spaces become hyphens):

```bash
grep '^### ' docs/GLOSSARY.md | sed 's/### //' | while read -r h; do
  anchor=$(echo "$h" | tr '[:upper:]' '[:lower:]' | sed 's/ /-/g; s/[^a-z0-9-]//g; s/--*/-/g')
  echo "$anchor"
done
```

Verify that every anchor listed in the spec's term tables appears in this output.

- [ ] **Step 3: Commit**

```bash
git add docs/GLOSSARY.md
git commit -m "Docs: add comprehensive glossary (~50 terms) for all audience levels"
```

---

## Task 2: Create `docs/FORMAL_ANALYSIS.md`

**Files:**
- Create: `docs/FORMAL_ANALYSIS.md`

This document states SimpleCipher's security properties in formal cryptographic notation. It references published proofs for primitives and provides protocol-level arguments for the composition.

**Important:** Read these source files before writing to ensure every claim matches the implementation:
- `src/crypto.h` (constants, function signatures, KDF construction comments at lines 21-36)
- `src/crypto.c` (chain_step at lines 80-83, make_commit at line 102, verify_commit at lines 107-114)
- `src/ratchet.h` (ratchet documentation at lines 8-48)
- `src/ratchet.c` (ratchet_step at lines 33-51, ratchet_send at lines 77-92, ratchet_receive at lines 94-124)
- `src/protocol.h` (frame format at lines 7-18, constants at lines 44-69)
- `src/protocol.c` (session_init at lines 83-128, frame_build at lines 147-212, frame_open at lines 224-300)

- [ ] **Step 1: Write the formal analysis document**

Create `docs/FORMAL_ANALYSIS.md` with sections covering notation, security definitions, assumptions, commitment scheme analysis, ratchet security, frame format security, known limitations, and references. Each section uses standard cryptographic notation. Every claim has either a proof sketch or an explicit reference. Known limitations are stated with the same rigor as security properties.

The document must:
- Open with audience statement and links to PROTOCOL.md and GLOSSARY.md
- Define notation: security parameter λ, advantage functions Adv, negligible function negl(λ)
- State IND-CCA2 and INT-CTXT definitions for the frame format
- State CDH assumption for X25519, PRF assumption for BLAKE2b, AEAD assumption for XChaCha20-Poly1305
- Analyze commitment scheme binding: `make_commit(pub) = BLAKE2b("cipher commit v3", pub)`, binding reduces to collision resistance of BLAKE2b
- Analyze SAS: 32-bit output, probability of MITM success ≤ 2^{-32} per session given honest SAS verification
- State forward secrecy: chain_step derives (mk, next) from chain key, old chain key is wiped, mk is one-time — reducing to PRF security of BLAKE2b
- State PCS: ratchet_send generates fresh X25519 keypair, new root derived from `BLAKE2b("cipher ratchet v2", root || DH(new_priv, peer_pub))` — recovery within 1 DH round-trip, reducing to CDH
- State frame security: nonce derived from sequence number (unique per key), AEAD provides IND-CCA2 + INT-CTXT
- State replay rejection: monotonic sequence counter, frame_open rejects seq != rx_seq
- Known limitations: MAC tolerance (MAX_AUTH_FAILURES=3), no PQ security, no deniability, 32-bit SAS, cover traffic timing bounds
- References: Signal Double Ratchet spec, Monocypher audit, Bernstein's Curve25519 paper, BLAKE2 paper

- [ ] **Step 2: Cross-check all constants against code**

Verify that every constant mentioned in the document matches `src/protocol.h` and `src/crypto.h`:

```bash
grep -n 'KEY\|NONCE_SZ\|MAC_SZ\|FRAME_SZ\|MAX_AUTH_FAILURES\|PROTOCOL_VERSION' src/protocol.h src/crypto.h
```

Expected: KEY=32, NONCE_SZ=24, MAC_SZ=16, FRAME_SZ=512, MAX_AUTH_FAILURES=3, PROTOCOL_VERSION=1.

- [ ] **Step 3: Commit**

```bash
git add docs/FORMAL_ANALYSIS.md
git commit -m "Docs: add formal security analysis for cryptographers and auditors"
```

---

## Task 3: Add intro paragraphs to technical docs

**Files:**
- Modify: `docs/HARDENING.md:1-4`
- Modify: `docs/THREAT_MODEL.md:1-4`
- Modify: `docs/ASSURANCE_MAP.md:1-4`

Add welcoming plain-English intro paragraphs that tell beginners whether they need this document.

- [ ] **Step 1: Add intro to HARDENING.md**

Insert after the title and audience line (after line 3), before "## Security notes":

```markdown

> SimpleCipher ships with many layers of protection built in — you don't need to configure anything. This document lists every security measure in detail, for auditors and developers who want to verify what's under the hood. **If you just want to chat securely, you don't need to read this** — see the [README](../README.md) to get started. For definitions of technical terms, see the [Glossary](GLOSSARY.md).
```

- [ ] **Step 2: Add intro to THREAT_MODEL.md**

Insert after the title and audience line (after line 3), before the first table:

```markdown

> Every security tool has limits. This document honestly states what SimpleCipher protects against, what it doesn't, and why. **If you're evaluating whether SimpleCipher is right for your situation**, start here. For definitions of technical terms, see the [Glossary](GLOSSARY.md).
```

- [ ] **Step 3: Add intro to ASSURANCE_MAP.md**

Insert after the title and audience line (after line 3), before the first table:

```markdown

> This is the evidence map — it shows exactly how each security claim is verified (tests, fuzzing, formal proofs, manual review). **If you want to trust SimpleCipher's claims, this is the receipt.** For definitions of technical terms, see the [Glossary](GLOSSARY.md).
```

- [ ] **Step 4: Commit**

```bash
git add docs/HARDENING.md docs/THREAT_MODEL.md docs/ASSURANCE_MAP.md
git commit -m "Docs: add beginner-friendly intro paragraphs to technical docs"
```

---

## Task 4: Add "New to cryptography?" callout to README

**Files:**
- Modify: `README.md:10-12`

- [ ] **Step 1: Add callout after the security notice**

Insert after line 10 (the security notice blockquote), before line 12 (the "single tiny binary" description):

```markdown

> **New to cryptography?** You don't need to understand any of the technical details to use SimpleCipher — just follow the steps below. If you're curious about how it works or want to learn, the [Walkthrough](docs/WALKTHROUGH.md) explains the protocol step by step, and the [Glossary](docs/GLOSSARY.md) defines every technical term.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "Docs: add 'New to cryptography?' callout to README for beginners"
```

---

## Task 5: Add inline glossary links — README.md

**Files:**
- Modify: `README.md`

Link the first occurrence of each technical term to the glossary. For files in the project root, use `docs/GLOSSARY.md#anchor`.

- [ ] **Step 1: Add glossary links to README.md**

Find and replace the **first occurrence** of each term (outside of code blocks and headings) with a glossary link. Key terms to link in this file:

- "end-to-end" → `[end-to-end encrypted](docs/GLOSSARY.md#end-to-end-encryption-e2ee)`
- "forward secrecy" (first occurrence) → `[forward secrecy](docs/GLOSSARY.md#forward-secrecy)`
- "X25519" → `[X25519](docs/GLOSSARY.md#x25519)`
- "XChaCha20-Poly1305" → `[XChaCha20-Poly1305](docs/GLOSSARY.md#xchacha20-poly1305)`
- "BLAKE2b" → `[BLAKE2b](docs/GLOSSARY.md#blake2b)`
- "ephemeral" (first occurrence) → `[ephemeral](docs/GLOSSARY.md#ephemeral)`
- "SAS" or "safety code" (first technical usage) → `[SAS](docs/GLOSSARY.md#sas-short-authentication-string)`
- "cover traffic" → `[cover traffic](docs/GLOSSARY.md#cover-traffic)`
- "Tor" (first occurrence) → `[Tor](docs/GLOSSARY.md#tor)`
- "SOCKS5" → `[SOCKS5](docs/GLOSSARY.md#socks5)`
- "Monocypher" → `[Monocypher](docs/GLOSSARY.md#monocypher)`
- "fingerprint" (first technical usage) → `[fingerprint](docs/GLOSSARY.md#fingerprint)`
- "MITM" or "man-in-the-middle" → `[MITM](docs/GLOSSARY.md#mitm-man-in-the-middle-attack)`

Do NOT link terms inside code blocks, command examples, or headings. Only link the first occurrence per term in the file.

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "Docs: add glossary links to README for discoverability"
```

---

## Task 6: Add inline glossary links — docs/PROTOCOL.md

**Files:**
- Modify: `docs/PROTOCOL.md`

PROTOCOL.md already has its own glossary section (lines 25-69) with inline explanations. The links here should point terms in the *formal* sections (line 71+) back to the glossary for readers who jumped straight there.

- [ ] **Step 1: Add glossary links to formal sections**

In the sections after line 71 (the formal protocol description), link the first occurrence of:

- "AEAD" → `[AEAD](GLOSSARY.md#aead-authenticated-encryption-with-associated-data)`
- "KDF" → `[KDF](GLOSSARY.md#kdf-key-derivation-function)`
- "nonce" → `[nonce](GLOSSARY.md#nonce-number-used-once)`
- "MAC" → `[MAC](GLOSSARY.md#mac-message-authentication-code)`
- "DH ratchet" → `[DH ratchet](GLOSSARY.md#ratchet-dh)`
- "forward secrecy" → `[forward secrecy](GLOSSARY.md#forward-secrecy)`
- "post-compromise security" → `[post-compromise security](GLOSSARY.md#post-compromise-security)`
- "commitment scheme" → `[commitment scheme](GLOSSARY.md#commitment-scheme)`
- "domain separation" → `[domain separation](GLOSSARY.md#domain-separation)`
- "DPI" → `[DPI](GLOSSARY.md#dpi-deep-packet-inspection)`
- "cover traffic" → `[cover traffic](GLOSSARY.md#cover-traffic)`
- "constant-time" → `[constant-time](GLOSSARY.md#constant-time)`

Do NOT modify the "Explain it like I'm 10" section or the glossary section — those are already well-written for their purpose.

- [ ] **Step 2: Commit**

```bash
git add docs/PROTOCOL.md
git commit -m "Docs: add glossary links to PROTOCOL.md formal sections"
```

---

## Task 7: Add inline glossary links — docs/HARDENING.md

**Files:**
- Modify: `docs/HARDENING.md`

This file has the highest density of unexplained acronyms. Link the first occurrence of each.

- [ ] **Step 1: Add glossary links**

Link first occurrences of these terms (outside code blocks):

- "ASLR" → `[ASLR](GLOSSARY.md#aslr-address-space-layout-randomization)`
- "RELRO" → `[RELRO](GLOSSARY.md#relro-relocation-read-only)`
- "DEP" → `[DEP](GLOSSARY.md#dep-data-execution-prevention)`
- "W^X" → `[W^X](GLOSSARY.md#wx-write-xor-execute)`
- "CET" → `[CET](GLOSSARY.md#cet-control-flow-enforcement-technology)`
- "BTI" → `[BTI](GLOSSARY.md#bti-branch-target-identification)`
- "seccomp" → `[seccomp](GLOSSARY.md#seccomp-secure-computing-mode)`
- "Capsicum" → `[Capsicum](GLOSSARY.md#capsicum)`
- "pledge" / "unveil" → `[pledge/unveil](GLOSSARY.md#pledge--unveil)`
- "LTO" → `[LTO](GLOSSARY.md#lto-link-time-optimization)`
- "PIE" → `[PIE](GLOSSARY.md#pie-position-independent-executable)`
- "DPI" → `[DPI](GLOSSARY.md#dpi-deep-packet-inspection)`
- "AddressSanitizer" → `[AddressSanitizer](GLOSSARY.md#sanitizer)`
- "UndefinedBehaviorSanitizer" → `[UndefinedBehaviorSanitizer](GLOSSARY.md#sanitizer)`
- "MemorySanitizer" → `[MemorySanitizer](GLOSSARY.md#sanitizer)`
- "CBMC" → link to description context (keep brief: "CBMC bounded model checker")
- "constant-time" → `[constant-time](GLOSSARY.md#constant-time)`
- "stack canaries" → `[stack canaries](GLOSSARY.md#stack-canary)`
- "JNI" → `[JNI](GLOSSARY.md#jni-java-native-interface)`

In the hardening table, link each acronym on its first table row appearance.

- [ ] **Step 2: Commit**

```bash
git add docs/HARDENING.md
git commit -m "Docs: add glossary links to HARDENING.md"
```

---

## Task 8: Add inline glossary links — docs/THREAT_MODEL.md

**Files:**
- Modify: `docs/THREAT_MODEL.md`

- [ ] **Step 1: Add glossary links**

Link first occurrences of:

- "MITM" → `[MITM](GLOSSARY.md#mitm-man-in-the-middle-attack)`
- "forward secrecy" → `[forward secrecy](GLOSSARY.md#forward-secrecy)`
- "post-compromise security" → `[post-compromise security](GLOSSARY.md#post-compromise-security)`
- "SAS" → `[SAS](GLOSSARY.md#sas-short-authentication-string)`
- "PIE" → `[PIE](GLOSSARY.md#pie-position-independent-executable)`
- "ASLR" → `[ASLR](GLOSSARY.md#aslr-address-space-layout-randomization)`
- "seccomp" → `[seccomp](GLOSSARY.md#seccomp-secure-computing-mode)`
- "Capsicum" → `[Capsicum](GLOSSARY.md#capsicum)`
- "pledge" → `[pledge](GLOSSARY.md#pledge--unveil)`
- "DPI" → `[DPI](GLOSSARY.md#dpi-deep-packet-inspection)`
- "cover traffic" → `[cover traffic](GLOSSARY.md#cover-traffic)`
- "mlockall" → link to glossary or explain inline ("locks memory to prevent swap")
- "X25519" → `[X25519](GLOSSARY.md#x25519)`
- "ephemeral" → `[ephemeral](GLOSSARY.md#ephemeral)`

- [ ] **Step 2: Commit**

```bash
git add docs/THREAT_MODEL.md
git commit -m "Docs: add glossary links to THREAT_MODEL.md"
```

---

## Task 9: Add inline glossary links — docs/ASSURANCE_MAP.md

**Files:**
- Modify: `docs/ASSURANCE_MAP.md`

- [ ] **Step 1: Add glossary links**

Link first occurrences of:

- "AEAD" → `[AEAD](GLOSSARY.md#aead-authenticated-encryption-with-associated-data)`
- "MAC" → `[MAC](GLOSSARY.md#mac-message-authentication-code)`
- "DH" / "ECDH" → `[DH](GLOSSARY.md#dh-diffie-hellman)`
- "PCS" → `[PCS](GLOSSARY.md#post-compromise-security)`
- "forward secrecy" → `[forward secrecy](GLOSSARY.md#forward-secrecy)`
- "SOCKS5" → `[SOCKS5](GLOSSARY.md#socks5)`
- "DPI" → `[DPI](GLOSSARY.md#dpi-deep-packet-inspection)`
- "constant-time" → `[constant-time](GLOSSARY.md#constant-time)`
- "CBMC" → add parenthetical "(bounded model checker)" on first use
- "ASan" → `[ASan](GLOSSARY.md#sanitizer)`
- "SAS" → `[SAS](GLOSSARY.md#sas-short-authentication-string)`
- "commitment" → `[commitment scheme](GLOSSARY.md#commitment-scheme)`
- "KDF" → `[KDF](GLOSSARY.md#kdf-key-derivation-function)`

- [ ] **Step 2: Commit**

```bash
git add docs/ASSURANCE_MAP.md
git commit -m "Docs: add glossary links to ASSURANCE_MAP.md"
```

---

## Task 10: Add inline glossary links — remaining docs

**Files:**
- Modify: `docs/BUILDING.md`
- Modify: `docs/DEPLOYMENT.md`
- Modify: `docs/DESIGN_BOUNDARIES.md`
- Modify: `docs/ANDROID.md`
- Modify: `docs/WALKTHROUGH.md`
- Modify: `SECURITY.md`

- [ ] **Step 1: Add glossary links to BUILDING.md**

Link first occurrences of:
- "musl" → `[musl](GLOSSARY.md#musl)`
- "LTO" → `[LTO](GLOSSARY.md#lto-link-time-optimization)`
- "RELRO" → `[RELRO](GLOSSARY.md#relro-relocation-read-only)`
- "NDK" → `[NDK](GLOSSARY.md#ndk-native-development-kit)`

- [ ] **Step 2: Add glossary links to DEPLOYMENT.md**

Link first occurrences of:
- "Tor" → `[Tor](GLOSSARY.md#tor)`
- "SOCKS5" → `[SOCKS5](GLOSSARY.md#socks5)`
- "DPI" → `[DPI](GLOSSARY.md#dpi-deep-packet-inspection)`
- "cover traffic" → `[cover traffic](GLOSSARY.md#cover-traffic)`
- "seccomp" → `[seccomp](GLOSSARY.md#seccomp-secure-computing-mode)`
- "ephemeral" → `[ephemeral](GLOSSARY.md#ephemeral)`
- "forward secrecy" → `[forward secrecy](GLOSSARY.md#forward-secrecy)`
- "fingerprint" → `[fingerprint](GLOSSARY.md#fingerprint)`
- "mlockall" → add inline note: "`mlockall` ([locks memory](GLOSSARY.md#seccomp-secure-computing-mode) to prevent secrets from being written to swap)"

- [ ] **Step 3: Add glossary links to DESIGN_BOUNDARIES.md**

Link first occurrences of:
- "ephemeral" → `[ephemeral](GLOSSARY.md#ephemeral)`
- "forward secrecy" → `[forward secrecy](GLOSSARY.md#forward-secrecy)`
- "SAS" → `[SAS](GLOSSARY.md#sas-short-authentication-string)`
- "MITM" → `[MITM](GLOSSARY.md#mitm-man-in-the-middle-attack)`
- "E2EE" → `[E2EE](GLOSSARY.md#end-to-end-encryption-e2ee)`

- [ ] **Step 4: Add glossary links to ANDROID.md**

Link first occurrences of:
- "APK" → `[APK](GLOSSARY.md#apk-android-package)`
- "JNI" → `[JNI](GLOSSARY.md#jni-java-native-interface)`
- "NDK" → `[NDK](GLOSSARY.md#ndk-native-development-kit)`
- "IME" → `[IME](GLOSSARY.md#ime-input-method-editor)`
- "SAS" → `[SAS](GLOSSARY.md#sas-short-authentication-string)`
- "SOCKS5" → `[SOCKS5](GLOSSARY.md#socks5)`
- "Tor" / "Orbot" → `[Tor](GLOSSARY.md#tor)`
- "fingerprint" → `[fingerprint](GLOSSARY.md#fingerprint)`
- "ephemeral" → `[ephemeral](GLOSSARY.md#ephemeral)`
- "cover traffic" → `[cover traffic](GLOSSARY.md#cover-traffic)`
- "forward secrecy" → `[forward secrecy](GLOSSARY.md#forward-secrecy)`
- "post-compromise security" → `[post-compromise security](GLOSSARY.md#post-compromise-security)`
- "seccomp" → `[seccomp](GLOSSARY.md#seccomp-secure-computing-mode)`

- [ ] **Step 5: Add glossary links to WALKTHROUGH.md**

Link first occurrences of:
- "Monocypher" → `[Monocypher](GLOSSARY.md#monocypher)`
- "X25519" → `[X25519](GLOSSARY.md#x25519)`
- "XChaCha20-Poly1305" → `[XChaCha20-Poly1305](GLOSSARY.md#xchacha20-poly1305)`
- "BLAKE2b" → `[BLAKE2b](GLOSSARY.md#blake2b)`
- "KDF" → `[KDF](GLOSSARY.md#kdf-key-derivation-function)`
- "AEAD" → `[AEAD](GLOSSARY.md#aead-authenticated-encryption-with-associated-data)`
- "nonce" → `[nonce](GLOSSARY.md#nonce-number-used-once)`
- "MAC" → `[MAC](GLOSSARY.md#mac-message-authentication-code)`
- "commitment" → `[commitment scheme](GLOSSARY.md#commitment-scheme)`
- "SAS" → `[SAS](GLOSSARY.md#sas-short-authentication-string)`
- "forward secrecy" → `[forward secrecy](GLOSSARY.md#forward-secrecy)`
- "post-compromise security" → `[post-compromise security](GLOSSARY.md#post-compromise-security)`
- "DH ratchet" → `[DH ratchet](GLOSSARY.md#ratchet-dh)`
- "chain ratchet" → `[chain ratchet](GLOSSARY.md#ratchet-symmetric--chain)`
- "seccomp" → `[seccomp](GLOSSARY.md#seccomp-secure-computing-mode)`
- "Capsicum" → `[Capsicum](GLOSSARY.md#capsicum)`

- [ ] **Step 6: Add glossary links to SECURITY.md**

Link first occurrences of (use `docs/GLOSSARY.md#` since this file is in the project root):
- "ASan" / "UBSan" / "MSan" → `[sanitizers](docs/GLOSSARY.md#sanitizer)`
- "CBMC" → add parenthetical "(bounded model checker)"
- "constant-time" → `[constant-time](docs/GLOSSARY.md#constant-time)`

- [ ] **Step 7: Commit all link additions**

```bash
git add docs/BUILDING.md docs/DEPLOYMENT.md docs/DESIGN_BOUNDARIES.md docs/ANDROID.md docs/WALKTHROUGH.md SECURITY.md
git commit -m "Docs: add glossary links to remaining docs (6 files)"
```

---

## Task 11: Final cross-check

**Files:**
- Read: all modified files

- [ ] **Step 1: Verify all glossary links resolve**

Run this command to extract every glossary link target from all docs and verify the anchor exists in GLOSSARY.md:

```bash
grep -roh 'GLOSSARY\.md#[a-z0-9-]*' docs/ README.md SECURITY.md | sort -u | while read -r link; do
  anchor="${link#GLOSSARY.md#}"
  if ! grep -qi "^### .*" docs/GLOSSARY.md | tr '[:upper:]' '[:lower:]' | sed 's/ /-/g; s/[^a-z0-9#-]//g' | grep -q "$anchor"; then
    echo "BROKEN: $link"
  fi
done
```

Fix any broken links found.

- [ ] **Step 2: Verify no links inside code blocks**

```bash
grep -n 'GLOSSARY\.md' docs/*.md README.md SECURITY.md | grep '`.*GLOSSARY.*`'
```

Expected: no output. If any matches, the link is inside a code span and should be removed.

- [ ] **Step 3: Spot-check readability**

Open these files and read the first 20 lines of each to verify the beginner flow works:
- README.md (should have security notice → "New to cryptography?" → description)
- docs/HARDENING.md (should have title → audience → welcoming intro → security notes)
- docs/THREAT_MODEL.md (should have title → audience → welcoming intro → table)
- docs/GLOSSARY.md (should have intro → "The Basics" section → plain-English definitions)

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -m "Docs: fix broken glossary links found in cross-check"
```

(Skip this step if no fixes were needed.)
