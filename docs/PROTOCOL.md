# Protocol and Security — SimpleCipher

> **Audience:** Students learning about encrypted P2P protocols, and cryptography/security experts auditing the design.

## Explain it like I'm 10

Imagine you and your friend want to pass secret notes in class, but a bully sits between you and can read or change anything you pass.

**The trick:** You and your friend each pick a secret number. You do some special math with your numbers that lets you both figure out the same secret code — without ever writing that code down or passing it. The bully sees the math fly by but can't figure out the code. (This is [key exchange](#glossary).)

**But wait** — what if the bully is clever? He could grab your math, throw it away, and send his own math to your friend, pretending to be you. Now he has a secret code with your friend AND a secret code with you. He reads everything in the middle.

**The fix:** Before you show your math, you each seal a promise in an envelope: *"My math will be THIS."* You swap envelopes, THEN show your math. If the bully tried to swap in his own math, the promise won't match — and you both know something's wrong. (This is the [commitment scheme](#glossary).)

**One more check:** After the math, both your screens show a short code — like `A3F2-91BC`. You call your friend on the phone: *"What's your code?"* If it matches, nobody's in the middle. (This is the [SAS](#glossary).)

**Now you chat.** Every message gets its own lock-and-key. After each message, you throw the key away. If someone steals a key later, they can only open that one message — not any of the others. (This is [forward secrecy](#glossary).) And every time you take turns talking, you make brand-new keys from scratch, so even if someone stole your current key, the next round of keys is safe. (This is [post-compromise security](#glossary).)

**When you're done,** the keys vanish from memory. Nothing was ever written to the desk. There's nothing left to find. (This is [ephemeral](#glossary).)

That's SimpleCipher. The rest of this document explains exactly how each piece works, with the real math and the real code.

---

## Glossary

If you're new to cryptography, start here. Every term used in this document is explained in plain English with an analogy. Terms in the body text are [linked](#x25519) back here.

<a id="x25519"></a>**X25519** — A key exchange algorithm. Two people each generate a random keypair (private + public). They exchange public keys, and both compute the same shared secret — without ever sending it over the wire. Based on elliptic-curve math (Curve25519).
> *Analogy:* Two people each mix a secret paint color into a shared base. They swap results, then each mixes in their own secret again — both arrive at the same final color. Nobody watching can figure it out.

<a id="xchacha20-poly1305"></a>**XChaCha20-Poly1305** — An [authenticated encryption](#aead) algorithm. Encrypts a message so only the keyholder can read it, AND produces a tag ([MAC](#mac)) that detects any tampering. "XChaCha20" scrambles the data; "Poly1305" proves it wasn't modified.
> *Analogy:* A locked box with a tamper-evident seal. Only the keyholder can open it, and if anyone messes with the seal, the recipient knows immediately.

<a id="blake2b"></a>**BLAKE2b** — A hash function. Takes any input and produces a fixed 32-byte fingerprint. Same input always gives the same output, but you can't reverse it. Used for [commitments](#commitment-scheme), [key derivation](#kdf), and fingerprints.
> *Analogy:* A paper shredder that always produces the same confetti pattern for the same document. You can verify a document matches its confetti, but you can't reconstruct the document from confetti.

<a id="kdf"></a>**KDF** (Key Derivation Function) — Takes one secret and derives multiple independent keys from it. SimpleCipher uses [BLAKE2b](#blake2b) as its KDF: the shared secret goes in, and separate keys for sending, receiving, and the [SAS](#sas) come out. Knowing one derived key reveals nothing about the others.
> *Analogy:* A master key that opens a key-cutting machine. Put in the master key and a label ("front door", "back door"), and each label produces a different cut.

<a id="nonce"></a>**Nonce** — "Number used once." A value that must never repeat with the same key. In SimpleCipher, each message uses a different key (from the chain [ratchet](#ratchet)), so the nonce is just the sequence number — the (key, nonce) pair is always unique.
> *Analogy:* A serial number on a check. Using the same serial twice would let the bank detect fraud.

<a id="mac"></a>**MAC** (Message Authentication Code) — A short tag appended to each message that proves it wasn't tampered with. Poly1305 computes the MAC; the receiver recomputes it and compares. If they differ, the message was modified.
> *Analogy:* A wax seal on a letter. If the seal is broken, you know someone opened it.

<a id="forward-secrecy"></a>**Forward secrecy** — Compromising today's key cannot decrypt yesterday's messages. The chain [ratchet](#ratchet) derives a fresh key per message, uses it once, and wipes it. Old keys don't exist anymore.
> *Analogy:* Burning the key after locking each box. Even if someone steals your current key, the old boxes are sealed forever.

<a id="post-compromise-security"></a>**Post-compromise security** — Stealing a key now does not let you read future messages. The DH [ratchet](#ratchet) mixes fresh randomness on each direction switch, creating a new chain the attacker cannot predict.
> *Analogy:* Changing all the locks after a break-in. The thief's copied key no longer works.

<a id="commitment-scheme"></a>**Commitment scheme** — Two phases: first commit (send a [hash](#blake2b) of your value), then reveal (send the actual value). The receiver checks the hash matches. Prevents changing your mind after seeing the other side's value. In SimpleCipher, both sides commit to their public keys before revealing them.
> *Analogy:* Sealing your answer in an envelope before seeing the other person's answer. You can't cheat after the fact.

<a id="sas"></a>**SAS** (Short Authentication String) — A short code derived from the shared secret, displayed on both screens. Users compare it out-of-band (phone, video). If it matches, no one is in the middle. 32 bits is enough because the [commitment scheme](#commitment-scheme) prevents brute-force search.
> *Analogy:* A serial number printed on both sides of a secure phone call. Same number = no one's listening.

<a id="ratchet"></a>**Ratchet** — A mechanism that only moves forward. Derives new keys from old ones, then wipes the old. SimpleCipher has two: the *chain ratchet* ([forward secrecy](#forward-secrecy) per message) and the *DH ratchet* ([post-compromise security](#post-compromise-security) per direction switch). Together: a "Double Ratchet" — the same architecture Signal uses.
> *Analogy:* A turnstile. You can walk through, but you can't walk back.

<a id="ephemeral"></a>**Ephemeral** — Temporary, not stored. Keys are generated fresh each session, held only in RAM, wiped on exit. Nothing written to disk. Device seized after session = nothing to find.
> *Analogy:* A sandcastle. It exists while you're building it, then the tide takes it.

<a id="aead"></a>**AEAD** (Authenticated Encryption with Associated Data) — Encryption that also authenticates. [XChaCha20-Poly1305](#xchacha20-poly1305) is an AEAD cipher. The "associated data" is authenticated but not encrypted — in SimpleCipher, the sequence number is AD (visible but tamper-proof).
> *Analogy:* A transparent envelope with a tamper seal. Everyone can see the address, but only the recipient can read the letter, and any tampering breaks the seal.

<a id="seccomp"></a>**Seccomp / Capsicum / pledge** — OS-level syscall sandboxes. After the handshake, the process restricts itself to only the syscalls it needs (read, write, poll, close). Code execution cannot open files, spawn processes, or make new connections.
> *Analogy:* A room where the only tools left are a pen and paper. Even if someone breaks in, they can't use power tools — the tools aren't in the room.

## How it works

SimpleCipher implements a complete encrypted chat protocol across a handful of focused C modules. Here is what happens when two people connect:

### 1. Key exchange

Each side generates a random [X25519](#x25519) keypair for this session only. The private key never leaves the machine. Through the mathematics of elliptic-curve Diffie-Hellman, both sides compute the same shared secret without ever transmitting it.

### 2. Commitment scheme (anti-MITM)

Before revealing public keys, each side sends a [hash](#blake2b) ([commitment](#commitment-scheme)) of their key. This prevents a man-in-the-middle from seeing one key and then crafting a fake key that produces a matching safety code. The commitment locks both sides into their keys before the reveal. The version byte and commitment are sent together in a single exchange so that version-mismatch and commitment-mismatch failures are timing-indistinguishable from the wire.

```
Round 1:  Alice -> version || H(key_A)    Bob -> version || H(key_B)    (commit)
Round 2:  Alice -> key_A                  Bob -> key_B                  (reveal)
Verify:   H(revealed_key) == commitment                                (both sides)
```

### Full handshake sequence

This is exactly what goes over the wire. Each arrow is one TCP write.

```
        Alice                              Bob
          |                                  |
          |--- version + H(pub_A) [33B] --->|  commit
          |<-- version + H(pub_B) [33B] ----|  (locked in)
          |                                  |
          |--- pub_A [32B] ---------------->|  reveal
          |<-- pub_B [32B] -----------------|
          |                                  |
          |  verify version matches          |  both sides
          |  verify H(pub_B) == commitment   |
          |  verify H(pub_A) == commitment   |
          |                                  |
          |  dh  = X25519(priv, peer_pub)    |  both compute
          |  prk = BLAKE2b(dh || both pubs)  |  domain-separated
          |  SAS = expand(prk, "sas")[:4]    |  same value
          |                                  |
          |  [optional: verify fingerprint]  |
          |                                  |
          |====== compare SAS out-of-band ===|  phone / video
          |                                  |
          |======= encrypted chat ===========|  XChaCha20-Poly1305
```

Both rounds always complete before any verification. This makes version-mismatch and commitment-mismatch failures timing-indistinguishable from the wire — an observer cannot tell *why* a handshake failed, only that it did.

If a man-in-the-middle tries to intercept, they must commit to their fake keys before seeing Alice's or Bob's real keys. They cannot adapt after the fact, so the SAS codes on Alice's and Bob's screens will differ — and the humans catch it.

### 3. Safety code verification

A [short authentication string (SAS)](#sas) is derived from the shared secret and displayed as `XXXX-XXXX`. Both people compare this code through a trusted channel — ideally a video call (you see and hear the person), or a voice call (you recognize their voice). A 32-bit code space is sufficient because the [commitment scheme](#commitment-scheme) prevents brute-force search.

### 4. Encrypted messaging with forward secrecy and post-compromise security

Messages are encrypted with [XChaCha20-Poly1305](#xchacha20-poly1305) using a two-layer [ratchet](#ratchet):

**Layer 1 — Symmetric chain ratchet ([forward secrecy](#forward-secrecy)):**

Each message derives a fresh encryption key from the current chain key, then the chain steps forward and the old key is wiped. Compromising one key reveals nothing about past messages.

```
chain[0]  -->  message_key[0]  (encrypt message 0, then wipe)
   |
chain[1]  -->  message_key[1]  (encrypt message 1, then wipe)
   |
chain[2]  -->  ...
```

**Layer 2 — DH ratchet ([post-compromise security](#post-compromise-security)):**

When the conversation direction switches (Alice was listening, now she replies), the sender generates a fresh [X25519](#x25519) keypair and mixes the new shared secret into a root key. This derives a completely new chain that an attacker cannot predict, even if they stole the old chain key.

```
Alice sends  ──►  DH ratchet  ──►  new tx chain  ──►  symmetric ratchet
Bob replies  ──►  DH ratchet  ──►  new tx chain  ──►  symmetric ratchet
Alice sends  ──►  DH ratchet  ──►  new tx chain  ──►  symmetric ratchet
```

Together, this is the same "Double Ratchet" architecture that Signal uses: [forward secrecy](#forward-secrecy) (past messages stay safe) plus [post-compromise security](#post-compromise-security) (future messages recover after key theft).

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
- Frame injection during idle — MAC failure tolerance (3 consecutive failures before teardown) prevents a single forged frame from killing the session

**SimpleCipher does NOT defend against:**
- An adversary present at session start who can substitute keys AND prevent SAS verification (if the user skips verification, all bets are off)
- An adversary who controls the peer's device (the peer IS the adversary)
- OS-level forensic artifacts (swap, terminal scrollback, shell history) — mitigated by `mlockall`, syscall sandboxing (seccomp/Capsicum/pledge), and interactive prompt, but not eliminated
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
| **Confidentiality** | [XChaCha20-Poly1305](#xchacha20-poly1305) [authenticated encryption](#aead) |
| **Key agreement** | [X25519](#x25519) [ephemeral](#ephemeral) Diffie-Hellman |
| **Authentication** | [Commit](#commitment-scheme)-then-reveal [SAS](#sas) verified out-of-band |
| **[Forward secrecy](#forward-secrecy)** | Chain-key [ratchet](#ratchet); each message key is used once then wiped |
| **Integrity** | Poly1305 [MAC](#mac) detects any tampering; sequence numbers reject replays |
| **Message-length hiding** | Fixed 512-byte frames prevent length-based analysis |
| **Terminal safety** | Peer messages are sanitized (non-printable bytes replaced with `.`) |
| **[Post-compromise security](#post-compromise-security)** | DH [ratchet](#ratchet) mixes fresh [X25519](#x25519) entropy on each direction switch |
| **Frame injection resistance** | [MAC](#mac) failures are tolerated (up to 3); a single forged frame does not kill the session |
| **Handshake indistinguishability** | Version and [commitment](#commitment-scheme) bundled in one round; all failure modes have identical timing |
| **[Ephemeral](#ephemeral) keys** | New keypair every session; nothing stored to disk |

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

In addition to [SAS](#sas) comparison, peers can exchange fingerprints out-of-band before connecting. A fingerprint is the first 8 bytes of [BLAKE2b](#blake2b)`_keyed(label="cipher fingerprint v2", pub_key)` formatted as `XXXX-XXXX-XXXX-XXXX`. The domain label ensures the fingerprint hash is distinct from all other hashes in the protocol. Since the fingerprint is derived from the public key (which is exchanged openly during the handshake), it has zero secret value — sharing it on paper, QR code, or any channel carries no risk.

After the commitment and key exchange phases, the native layer compares the received peer public key's fingerprint against the pre-shared value using a constant-time comparison. If they match, the SAS step is skipped. If they don't match, the connection is aborted immediately.

This provides 64 bits of entropy (vs 32 for SAS) and removes the human comparison step, making it stronger when pre-arrangement is possible.

### What it does NOT provide

- **Post-compromise security is per-session**: the DH ratchet recovers from key theft within a session, but there is no cross-session recovery. Each session starts fresh — if an attacker is present at session start, the entire session is compromised. This is inherent to the ephemeral design.
- **Anonymity**: IP addresses are visible on the network. For anonymity, run over Tor: `simplecipher connect --socks5 127.0.0.1:9050` (enables cover traffic automatically). Listeners behind onion services should add `--cover-traffic`.
- **Identity persistence**: there are no long-term keys or contacts. Each session is independent. This is deliberate — a stored identity key is a forensic artifact (proof you use the tool, and a target for impersonation if seized). The SAS verification on every connect *is* the identity model: human-verified, not key-pinned, and it leaves nothing on disk. If you need persistent contacts with key pinning, use Signal.
- **Android memory hygiene**: the desktop builds use `crypto_wipe()` on every buffer to ensure plaintext and keys do not linger in RAM. The Android build runs on the JVM, where Strings are immutable and garbage-collected — sensitive data cannot be reliably zeroed. The app clears widgets and blocks screenshots (`FLAG_SECURE`), but this is best-effort. Android also lacks `mlockall()`, so key material can be swapped to disk under memory pressure. For the strongest memory guarantees, use the desktop CLI or TUI.
- **Forced termination**: if the process is killed by `SIGKILL` (kill -9), the OOM killer, or a system force-stop, `crypto_wipe()` never runs — these signals cannot be caught. Key material remains in freed physical pages until the kernel reclaims and zeroes them (not guaranteed to be immediate). `CIPHER_HARDEN` mitigates: `mlockall` prevents swap, `RLIMIT_CORE=0` prevents crash dumps, `PR_SET_DUMPABLE=0` blocks ptrace. But a cold-boot attack or DMA access to physical RAM during this window is theoretically possible. Power off the device after a session if this matters.

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
7. `platform.h` — OS abstraction (sockets, RNG, signals, sandboxing)

Each module can be read and understood independently. Every header has a teaching-style comment block explaining what the module does, why it exists, and what to read next.
