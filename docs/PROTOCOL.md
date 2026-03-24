# Protocol and Security — SimpleCipher

> **Audience:** Students learning about encrypted P2P protocols, and cryptography/security experts auditing the design.

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

### Full handshake sequence

This is exactly what goes over the wire. Each arrow is one TCP write.

```
        Alice                              Bob
          |                                  |
          |-------- protocol version ------->|
          |<------- protocol version --------|
          |                                  |
          |-------- H(pub_A) --------------->|  commitment
          |<------- H(pub_B) ----------------|  (locked in)
          |                                  |
          |-------- pub_A ------------------>|  reveal
          |<------- pub_B -------------------|
          |                                  |
          |  verify H(pub_B) == commitment   |  both sides
          |  verify H(pub_A) == commitment   |
          |                                  |
          |  shared = X25519(priv, peer_pub) |  both compute
          |  SAS = BLAKE2b(shared)[:4]       |  same value
          |                                  |
          |  [optional: verify fingerprint]  |
          |                                  |
          |====== compare SAS out-of-band ===|  phone / video
          |                                  |
          |======= encrypted chat ===========|  XChaCha20-Poly1305
```

If a man-in-the-middle tries to intercept, they must commit to their fake keys before seeing Alice's or Bob's real keys. They cannot adapt after the fact, so the SAS codes on Alice's and Bob's screens will differ — and the humans catch it.

### 3. Safety code verification

A short authentication string (SAS) is derived from the shared secret and displayed as `XXXX-XXXX`. Both people compare this code through a trusted channel — ideally a video call (you see and hear the person), or a voice call (you recognize their voice). A 32-bit code space is sufficient because the commitment scheme prevents brute-force search.

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

## Threat model

SimpleCipher protects the contents and authenticity of a conversation between two people who can verify each other's identity through a trusted channel (video call, voice call, or pre-shared fingerprint).

**The adversary can:**
- Observe all network traffic between the two peers (passive eavesdropping)
- Modify, replay, reorder, or inject network packets (active MITM)
- Record all encrypted traffic for later analysis (harvest-now-decrypt-later)
- Compromise one peer's device after the session ends (device seizure)
- Compromise one peer's device during a session (RAM extraction)

**SimpleCipher defends against:**
- Eavesdropping — XChaCha20-Poly1305 encryption with ephemeral keys
- Active MITM — commitment scheme + SAS verification prevents key substitution
- Harvest-now-decrypt-later — forward secrecy (chain ratchet wipes old keys)
- Post-session device seizure — no keys on disk, nothing to find
- Mid-session RAM compromise — DH ratchet recovers after the next direction switch

**SimpleCipher does NOT defend against:**
- An adversary present at session start who can substitute keys AND prevent SAS verification (if the user skips verification, all bets are off)
- An adversary who controls the peer's device (the peer IS the adversary)
- OS-level forensic artifacts (swap, terminal scrollback, shell history) — mitigated by `mlockall`, seccomp, and interactive prompt, but not eliminated
- Traffic analysis beyond message length (timing, frequency, endpoints visible unless using Tor)
- An adversary who compromises both directions simultaneously mid-session (DH ratchet recovers on direction switch, not instantly)

**Assumptions:**
- The OS CSPRNG (`getrandom`/`getentropy`/`BCryptGenRandom`) produces cryptographically secure random bytes
- Monocypher's X25519, XChaCha20-Poly1305, and BLAKE2b implementations are correct (audited by Cure53)
- The user actually compares the SAS code out-of-band and does not skip verification
- TCP delivers bytes reliably and in order (the protocol has no reorder/retransmit logic)

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

### Key lifecycle

Every key and secret has a defined lifetime. Nothing persists beyond its purpose.

| Key material       | Created           | Wiped                 | Lifetime       |
|--------------------|-------------------|-----------------------|----------------|
| ephemeral privkey  | gen_keypair()     | after session_init    | handshake only |
| ephemeral pubkey   | gen_keypair()     | cleanup               | handshake only |
| commitment hash    | make_commit()     | after verify          | handshake only |
| shared DH secret   | session_init()    | after key expansion   | never stored   |
| SAS key            | expand(shared)    | after format_sas      | handshake only |
| chain key (tx/rx)  | expand(shared)    | after next message    | one message    |
| message key        | chain_step()      | after encrypt/decrypt | one frame      |
| ratchet DH privkey | ratchet_step()    | after next ratchet    | one direction  |
| fingerprint hash   | domain_hash()     | after compare/format  | immediate      |
| peer fingerprint   | nativeSetPeerFp() | after compare         | handshake only |

Nothing is stored to disk, ever.

### Fingerprint verification (optional)

In addition to SAS comparison, peers can exchange fingerprints out-of-band before connecting. A fingerprint is the first 8 bytes of `BLAKE2b(pub_key)` formatted as `XXXX-XXXX-XXXX-XXXX`. Since the fingerprint is derived from the public key (which is exchanged openly during the handshake), it has zero secret value — sharing it on paper, QR code, or any channel carries no risk.

After the commitment and key exchange phases, the native layer compares the received peer public key's fingerprint against the pre-shared value using a constant-time comparison. If they match, the SAS step is skipped. If they don't match, the connection is aborted immediately.

This provides 64 bits of entropy (vs 32 for SAS) and removes the human comparison step, making it stronger when pre-arrangement is possible.

### What it does NOT provide

- **Post-compromise security is per-session**: the DH ratchet recovers from key theft within a session, but there is no cross-session recovery. Each session starts fresh — if an attacker is present at session start, the entire session is compromised. This is inherent to the ephemeral design.
- **Anonymity**: IP addresses are visible on the network. For anonymity, run over Tor: `torsocks simplecipher connect ...`
- **Identity persistence**: there are no long-term keys or contacts. Each session is independent. This is deliberate — a stored identity key is a forensic artifact (proof you use the tool, and a target for impersonation if seized). The SAS verification on every connect *is* the identity model: human-verified, not key-pinned, and it leaves nothing on disk. If you need persistent contacts with key pinning, use Signal.
- **Android memory hygiene**: the desktop builds use `crypto_wipe()` on every buffer to ensure plaintext and keys do not linger in RAM. The Android build runs on the JVM, where Strings are immutable and garbage-collected — sensitive data cannot be reliably zeroed. The app clears widgets and blocks screenshots (`FLAG_SECURE`), but this is best-effort. For the strongest memory guarantees, use the desktop CLI or TUI.

### Cryptographic library

The only dependency is [Monocypher](https://monocypher.org/) (vendored as `lib/monocypher.c`):

- Public domain (BSD-2-Clause / CC0 dual-licensed)
- [Audited by Cure53](https://monocypher.org/quality-assurance/audit)
- Constant-time implementations throughout
- Provides: X25519, XChaCha20-Poly1305, BLAKE2b, secure wipe

No OpenSSL, no libsodium, no dynamic linking. The entire cryptographic stack is vendored in `lib/` and links statically.

## Reading the source code

Recommended reading order:

1. `main.c` — session lifecycle, arg parsing
2. `protocol.h` — wire format, frame layout, session key derivation
3. `crypto.h` — cryptographic building blocks (KDF, ratchet, SAS)
4. `ratchet.h` — DH ratchet for post-compromise security
5. `network.h` — TCP socket I/O
6. `tui.h` / `cli.h` — user interface event loops
7. `platform.h` — OS abstraction (sockets, RNG, signals, seccomp)

Each module can be read and understood independently. Every header has a teaching-style comment block explaining what the module does, why it exists, and what to read next.
