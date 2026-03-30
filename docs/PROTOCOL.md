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

<a id="ephemeral"></a>**Ephemeral** — Temporary, not stored. Keys are generated fresh each session, held only in RAM, wiped on exit. Nothing written to disk. Device seized after session = nothing to find *in the application* (OS-level artifacts like swap, terminal scrollback, and Android heap residue are outside SimpleCipher's control — see [What it does NOT provide](#what-it-does-not-provide)).
> *Analogy:* A sandcastle. It exists while you're building it, then the tide takes it.

<a id="aead"></a>**AEAD** (Authenticated Encryption with Associated Data) — Encryption that also authenticates. [XChaCha20-Poly1305](#xchacha20-poly1305) is an AEAD cipher. The "associated data" is authenticated but not encrypted — in SimpleCipher, the sequence number is AD (visible but tamper-proof).
> *Analogy:* A transparent envelope with a tamper seal. Everyone can see the address, but only the recipient can read the letter, and any tampering breaks the seal.

<a id="seccomp"></a>**Seccomp / Capsicum / pledge** — OS-level syscall sandboxes. After the handshake, the process restricts itself to a minimal syscall set: I/O (read, write, poll, close, shutdown), memory management (mmap, brk), signals, clock, and getrandom. Blocked: open, connect, socket, execve, ptrace, and all filesystem access. The exact allow-list is in `platform.c` (phase 2 filter). Code execution cannot open files, spawn processes, or make new connections.
> *Analogy:* A room where the only tools left are a pen and paper. Even if someone breaks in, they can't use power tools — the tools aren't in the room.

## How it works

SimpleCipher implements a complete encrypted chat protocol across a handful of focused C modules. Here is what happens when two people connect:

### 1. Key exchange

Each side generates a random [X25519](#x25519) keypair for this session only. The private key never leaves the machine. Through the mathematics of elliptic-curve Diffie-Hellman, both sides compute the same shared secret without ever transmitting it.

### 2. Commitment scheme (anti-MITM)

Before revealing public keys, each side sends a [hash](#blake2b) ([commitment](#commitment-scheme)) of their key and a random nonce. The commitment is `H(pub || nonce)` — binding the key to a fresh random value prevents a man-in-the-middle from seeing one key and then crafting a fake key that produces a matching safety code. The commitment locks both sides into their keys before the reveal. The version byte, commitment, and nonce are sent together in a single exchange so that version-mismatch and commitment-mismatch failures are timing-indistinguishable from the wire.

```
Round 1:  Alice -> version || H(pub_A || nonce_A || version) || nonce_A    Bob -> version || H(pub_B || nonce_B || version) || nonce_B    (commit)
Round 2:  Alice -> pub_A                                        Bob -> pub_B                                        (reveal)
Verify:   H(revealed_pub || nonce || version) == commitment                                (both sides)
```

### Full handshake sequence

This is what goes over the wire. Each arrow is one exchange round. Payload sizes are shown; actual wire bytes are larger due to random padding (see [Wire padding](#6-wire-padding-dpi-resistance)).

```
        Alice                              Bob
          |                                  |
          |--- version + H(pub_A||nonce_A||ver) + nonce_A [65B] --->|  commit
          |<-- version + H(pub_B||nonce_B||ver) + nonce_B [65B] ----|  (locked in)
          |                                  |
          |--- pub_A [32B] ---------------->|  reveal
          |<-- pub_B [32B] -----------------|
          |                                  |
          |  verify version matches          |  both sides
          |  verify H(pub_B||nonce_B||ver) == commitment   |  (Bob's key)
          |  verify H(pub_A||nonce_A||ver) == commitment   |  (Alice's key)
          |                                  |
          |  dh  = X25519(priv, peer_pub)    |  both compute
          |  ikm = dh || both pubs || both nonces || version
          |  prk = BLAKE2b(ikm)              |  domain-separated
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

**Note on eager pre-computation:** The DH ratchet step (X25519 keypair generation, DH computation, KDF) is performed eagerly upon receiving a frame, not deferred to send time. The results are staged in session memory and committed when the next frame is built. This eliminates timing differences between ratcheted and non-ratcheted sends, but means the staged private key exists in RAM from receive time until the next send. A RAM compromise in that window can recover the next outbound ratchet state — PCS recovery requires both a send *and* no compromise of the staged state.

**Note on recovery timing:** The ratchet key is included in a frame encrypted with the pre-ratchet chain. The receiver derives the new chain only after decrypting that frame, so the first post-ratchet message is encrypted under the old chain — recovery takes effect from the second message onward.

```
Alice sends  ──►  DH ratchet  ──►  new tx chain  ──►  symmetric ratchet
Bob replies  ──►  DH ratchet  ──►  new tx chain  ──►  symmetric ratchet
Alice sends  ──►  DH ratchet  ──►  new tx chain  ──►  symmetric ratchet
```

Together, this is the same "Double Ratchet" architecture that Signal uses: [forward secrecy](#forward-secrecy) (past messages stay safe) plus [post-compromise security](#post-compromise-security) (future messages recover after key theft).

#### How the two ratchets work together

A 6-message exchange showing both ratchets in action:

```
Alice                                                    Bob
-----                                                    ---

[DH ratchet] gen ek_A1, derive new root + tx chain
  |
  |  msg 1: chain_step(ck_A[0]) -> mk_1 + ck_A[1]
  |          encrypt with mk_1, wipe mk_1
  |          frame includes ek_A1              -------->  decrypt with mk_1
  |                                                       wipe mk_1
  |  msg 2: chain_step(ck_A[1]) -> mk_2 + ck_A[2]
  |          encrypt with mk_2, wipe mk_2
  |          (no DH ratchet -- same direction) -------->  decrypt with mk_2
  |                                                       wipe mk_2
  |
  |                                          [DH ratchet] gen ek_B1,
  |                                            derive new root + tx chain
  |                                                       |
  |          decrypt with mk_3               <--------  msg 3: chain_step(ck_B[0])
  |          wipe mk_3                                    -> mk_3 + ck_B[1]
  |                                                       encrypt, wipe mk_3
  |          decrypt with mk_4               <--------  msg 4: chain_step(ck_B[1])
  |          wipe mk_4                                    -> mk_4 + ck_B[2]
  |                                                       encrypt, wipe mk_4
  |
[DH ratchet] gen ek_A2, derive new root + tx chain
  |
  |  msg 5: chain_step(ck_A2[0]) -> mk_5 + ck_A2[1]
  |          encrypt with mk_5, wipe mk_5     -------->  decrypt with mk_5
  |                                                       wipe mk_5
  |  msg 6: chain_step(ck_A2[1]) -> mk_6 + ck_A2[2]
  |          encrypt with mk_6, wipe mk_6     -------->  decrypt with mk_6
  |                                                       wipe mk_6
```

**Legend:**

| Symbol | Meaning |
|--------|---------|
| `[DH ratchet]` | Direction switch: generate fresh X25519 keypair, derive new root and chain |
| `ck_X[n]` | Chain key after n steps (X = sender) |
| `mk_N` | One-time message key for message N |
| `ek_A1` | Alice's first ephemeral ratchet public key |
| `wipe` | `crypto_wipe()` — key erased from memory |

**Why both ratchets are needed:** The chain ratchet (vertical steps) gives [forward secrecy](GLOSSARY.md#forward-secrecy) — each message key is unique and wiped immediately, so stealing one reveals no others. The DH ratchet (direction switches) gives [post-compromise security](GLOSSARY.md#post-compromise-security-pcs) — fresh random keys mean that even a full key compromise is healed after one round-trip.

### 5. Fixed-size framing

Every frame is exactly 512 bytes regardless of message length:

```
[ sequence: 8 bytes | ciphertext: 488 bytes | MAC: 16 bytes ]
```

This hides message length from network observers. The sequence number is authenticated (tamper-proof) but not encrypted, enabling replay and reorder detection before any crypto work. Both `frame_build` and `frame_open` reject frames when the sequence counter reaches UINT64_MAX, preventing nonce reuse from counter overflow.

### 6. Wire padding (DPI resistance)

On the wire, every message (handshake and chat) is wrapped with random padding:

```
[ pad_len: 1 byte | payload | random_pad: 0-255 bytes ]
```

`pad_len` is a raw CSPRNG byte (uniformly distributed 0-255) and is not encrypted — it is sent in cleartext so the receiver knows where the padding ends. The padding bytes are CSPRNG output. The random padding varies total message size from 513 to 768 bytes, which defeats naive fixed-size DPI rules but does not provide full traffic indistinguishability. The pad_len byte is a cleartext header, the 8-byte sequence number in the frame AD is also unencrypted, and the fixed 512-byte inner frame size is a distinguishing feature for a sophisticated observer.

Chat frames produce 513-768 bytes per message. Handshake exchanges produce 34-289 bytes (commit) or 33-288 bytes (key reveal). All sizes vary randomly.

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
- Post-session device seizure — no keys on disk; OS-level traces (swap, scrollback, Android heap) are best-effort mitigated but not guaranteed (see limitations below)
- Mid-session RAM compromise — [DH ratchet](GLOSSARY.md#ratchet-dh) recovers after the next direction switch
- Frame injection during idle — [MAC](GLOSSARY.md#mac-message-authentication-code) failure tolerance (3 consecutive failures before teardown) prevents a single forged frame from killing the session

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
| **[DPI](GLOSSARY.md#dpi-deep-packet-inspection) resistance** | 1-byte pad_len header + random padding varies wire size (513-768 bytes); defeats naive fixed-size DPI rules but pad_len and sequence number are cleartext |
| **Terminal safety** | Peer messages are sanitized (non-printable bytes replaced with `.`) |
| **[Post-compromise security](#post-compromise-security)** | DH [ratchet](#ratchet) mixes fresh [X25519](#x25519) entropy on each direction switch |
| **Frame injection resistance** | [MAC](#mac) failures are tolerated (up to 3); a single forged frame does not kill the session |
| **Handshake indistinguishability** | Version and [commitment](#commitment-scheme) bundled in one round; all failure modes have identical timing |
| **[Ephemeral](#ephemeral) keys** | New keypair every session; nothing stored to disk |
| **Sequence overflow rejection** | `frame_build` and `frame_open` reject at UINT64_MAX to prevent nonce reuse |
| **Terminal restore** | `verify.c` registers an `atexit` handler to restore terminal echo if the process exits during passphrase input |

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
| ratchet DH privkey | ratchet_send() / ratchet_receive() | after next ratchet    | one direction  |
| fingerprint hash   | domain_hash()     | after compare/format  | immediate      |
| peer fingerprint   | verify_peer_fingerprint() | after compare         | handshake only |

By default, nothing is stored to disk. The optional `keygen` command saves a passphrase-protected identity key file. On POSIX systems, `identity_save` writes to a temporary file and atomically renames it to the target path, preventing partial writes from corrupting an existing key file.

### Fingerprint verification (optional)

In addition to [SAS](#sas) comparison, peers can exchange fingerprints out-of-band before connecting. A fingerprint is the first 8 bytes of [BLAKE2b](#blake2b)`_keyed(label="cipher fingerprint v2", pub_key)` formatted as `XXXX-XXXX-XXXX-XXXX`. The domain label ensures the fingerprint hash is distinct from all other hashes in the protocol. Since the fingerprint is derived from the public key (which is exchanged openly during the handshake), it has zero secret value — sharing it on paper, QR code, or any channel carries no risk.

After the commitment and key exchange phases, the native layer compares the received peer public key's fingerprint against the pre-shared value using a [constant-time](GLOSSARY.md#constant-time) comparison. If they match, the connection proceeds to the SAS verification step (defence in depth — both layers verify). If they don't match, the connection is aborted immediately.

This provides 64 bits of entropy (vs 32 for SAS). Combined with SAS confirmation, both automated and human verification must pass before the session begins.

### What it does NOT provide

- **Post-compromise security is per-session**: the DH ratchet recovers from key theft within a session, but there is no cross-session recovery. Each session starts fresh — if an attacker is present at session start, the entire session is compromised. This is inherent to the ephemeral design.
- **Anonymity**: IP addresses are visible on the network. For anonymity, run over Tor: `simplecipher connect --socks5 127.0.0.1:9050` (enables [cover traffic](GLOSSARY.md#cover-traffic) automatically). Listeners behind onion services should add `--cover-traffic`.
- **Identity persistence**: by default, there are no long-term keys — each session generates a fresh ephemeral keypair. The optional `keygen` / `--identity` feature creates a persistent identity key for stable fingerprints (see Note below), but this is opt-in. Without it, the SAS verification on every connect *is* the identity model: human-verified, not key-pinned, and it leaves nothing on disk.

> **Note:** The `keygen` command creates an *optional* persistent identity key for users who need stable [fingerprints](GLOSSARY.md#fingerprint) across sessions (e.g., paper fingerprint workflow). When loaded via `--identity`, the identity key **is** the handshake keypair -- the same [X25519](GLOSSARY.md#x25519) private key used for [Diffie-Hellman](GLOSSARY.md#diffie-hellman-dh) key exchange. The DH shared secret between two peers using the same identity keys is deterministic (same priv + same peer pub = same DH output), but session nonces (random per-session values mixed into the [KDF](GLOSSARY.md#kdf-key-derivation-function)) ensure that derived keys differ every session. Forward secrecy is preserved because the [chain ratchet](GLOSSARY.md#ratchet-symmetricchain) and [DH ratchet](GLOSSARY.md#ratchet-dh) still derive and wipe per-message keys. **Theft of the key file plus the passphrase allows impersonation in future sessions.** Theft of the key file alone requires brute-forcing [Argon2id](GLOSSARY.md#argon2id) (100 MB memory, 3 passes). See [DEPLOYMENT.md](DEPLOYMENT.md) for the use case.
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

1. `main.c` — session lifecycle; `args.h` — arg parsing; `verify.h` — verification
2. `protocol.h` — wire format, frame layout, session key derivation
3. `crypto.h` — cryptographic building blocks ([KDF](GLOSSARY.md#kdf-key-derivation-function), ratchet, SAS)
4. `ratchet.h` — DH ratchet for post-compromise security
5. `network.h` — TCP socket I/O
6. `nb_io.h` — non-blocking I/O for the POSIX chat loop
7. `tui.h` / `cli.h` — user interface event loops
8. `platform.h` — OS abstraction (sockets, RNG, signals, sandboxing)

Each module can be read and understood independently. Every header has a teaching-style comment block explaining what the module does, why it exists, and what to read next.
