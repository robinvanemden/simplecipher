# Code Walkthrough

A guided tour through SimpleCipher's source code. Start here if you want to understand how the protocol works by reading the implementation.

**Time:** ~1 hour for the core protocol, ~2 hours including hardening.

**Prerequisites:** Basic C (pointers, structs, functions). No cryptography background needed — everything is explained as we go.

---

## The 10-minute version

If you only read 4 functions, read these:

1. **`session_init()`** in `protocol.c` — derives all session keys from the [X25519](GLOSSARY.md#x25519) shared secret
2. **`frame_build()`** in `protocol.c` — encrypts one message into a 512-byte frame
3. **`frame_open()`** in `protocol.c` — decrypts and authenticates a received frame
4. **`chain_step()`** in `crypto.c` — the symmetric ratchet ([forward secrecy](GLOSSARY.md#forward-secrecy) in 3 steps)

These 4 functions are the entire protocol. Everything else is I/O, UI, or hardening.

---

## Part 1: Key Exchange (how two strangers get a shared secret)

**Files:** `main.c` (handshake), `verify.c` (SAS verification, fingerprint check), `crypto.h` (building blocks), `protocol.c` (session_init)

### Step 1: Generate an ephemeral keypair

```
main.c → gen_keypair(self_priv, self_pub)
```

Each side generates a fresh X25519 keypair from the OS random number generator. "Ephemeral" means it exists only for this session — never stored to disk, wiped from RAM on exit.

### Step 2: Commit before revealing

```
main.c → make_commit(commit_self, self_pub, self_nonce)
```

Before sending our public key, we send a *[commitment](GLOSSARY.md#commitment-scheme)* — `H(pub || nonce)`, binding the key to a fresh random value. This prevents a man-in-the-middle from seeing our key and adaptively choosing their own to produce a matching safety code. The commitment is binding: once sent, we can't change the key without the hash mismatching.

### Step 3: Exchange commitments, then keys

```
main.c:
  exchange(fd, we_init, [ver + commit + nonce + eph_pub], ...)  ← Round 1 (97 bytes)
  exchange(fd, we_init, AEAD_encrypt(self_pub, eph_key), ...)  ← Round 2 (48 bytes)
```

Round 1 includes an ephemeral X25519 public key. Both sides compute a temporary shared secret from the ephemeral Diffie-Hellman (DH) key exchange, then use it to encrypt the public key reveal in round 2. This prevents a passive network observer from seeing the public keys — important for `--identity` users whose key is stable across sessions. Both rounds complete before any verification, making failure modes indistinguishable on the wire.

### Step 4: Derive session keys

```
protocol.c → session_init()
```

Both sides compute the same shared secret via X25519, then derive:
- **[SAS](GLOSSARY.md#sas-short-authentication-string) key** — Short Authentication String for human verification (32 bits, displayed as `XXXX-XXXX`, e.g. `A3F2-91BC`)
- **Root key** — persists across [DH ratchet](GLOSSARY.md#ratchet-dh) steps
- **TX/RX chains** — per-direction, per-message forward secrecy

See the key derivation tree in `crypto.h` for the full picture.

### Step 5: Verify the safety code

Both sides display the same 8-character code (e.g., "A3F2-91BC"). The users compare it over a phone call or in person. If it matches, no one is in the middle. If it doesn't, someone replaced the keys.

---

## Part 2: Sending and Receiving Messages

**Files:** `protocol.c` (frame_build, frame_open), `crypto.c` (chain_step)

### Encrypting a message

```
protocol.c → frame_build(session, plaintext, len, frame_out, next_chain)
```

1. Check if a DH ratchet step is needed (see Part 3)
2. Derive a one-time message key: `chain_step(tx_chain) → message_key + next_chain`
3. Build the plaintext slot: `[flags | optional_ratchet_key | length | message | zero_padding]`
4. Encrypt with [XChaCha20-Poly1305](GLOSSARY.md#xchacha20-poly1305): `crypto_aead_lock(plaintext → ciphertext + MAC)`
5. Output: exactly 512 bytes — always, regardless of message length

The caller sends the frame over TCP. (During the handshake this uses `frame_send()`; during chat the POSIX loops use the non-blocking `nb_io` layer — see `nb_io.h` for details.) The frame is wrapped in random padding on the wire (513-768 bytes total), then the chain advance is committed (`tx = next_chain; tx_seq++`). If the send fails, the chain is not advanced — both sides stay in sync.

### Decrypting a message

```
protocol.c → frame_open(session, frame_in, plaintext_out, len_out)
```

1. Check sequence number (cheap replay rejection — no crypto needed)
2. Derive the expected message key from the RX chain
3. Decrypt and verify [MAC](GLOSSARY.md#mac-message-authentication-code): `crypto_aead_unlock(ciphertext → plaintext)`
4. Parse flags, optional ratchet key, length, message
5. Only on success: advance the RX chain and sequence number. On failure (tampered frame, wrong sequence number), nothing changes — the session state is untouched and the next legitimate frame still works.

### Forward secrecy (chain_step)

```
crypto.c → chain_step(chain, &message_key, &next_chain)
```

This is the symmetric ratchet in 3 steps:
- Derive a one-time message key from the current chain
- Derive the next chain value
- The old chain is overwritten — past messages can't be decrypted even if the current chain is stolen

---

## Part 3: The DH Ratchet (recovering from key compromise)

**Files:** `ratchet.h` (read the "WHY TWO RATCHETS?" comment), `ratchet.c`

The symmetric ratchet provides forward secrecy (can't go backwards). But if an attacker steals the current chain key, they can derive all *future* keys in that chain — it advances deterministically.

The DH ratchet fixes this. Each time the conversation switches direction (Alice was receiving, now she sends):

1. Generate a fresh X25519 keypair
2. Compute a new DH secret with the peer's latest ratchet key
3. Mix the DH secret into the root key
4. Derive a new sending chain from the new root

The attacker's stolen chain key is now useless — the new chain depends on a DH secret they don't have (it was just generated from fresh randomness).

**Key functions:**
- `ratchet_send()` — sender's half (generate keypair, derive new TX chain)
- `ratchet_receive()` — receiver's half (use peer's new key, derive new RX chain)

---

## Part 4: Network I/O (optional)

**Files:** `network.h/c`, `nb_io.h/c`

The network layer has two modes:

**Blocking helpers (handshake only):**
- `frame_send(fd, frame, deadline)` — send one 512-byte frame with random wire padding
- `frame_recv(fd, frame, deadline)` — receive one padded frame, strip padding
- `exchange(fd, initiator, out, in)` — handshake exchange (also padded)

**Non-blocking I/O (chat phase):**
- On POSIX, the chat loop uses `nb_io.h/c` — poll-based, non-blocking accumulation and drain. Frames are received byte-by-byte via `nb_try_recv()` and sent incrementally via `nb_try_send()`, with monotonic deadline checks throughout.
- On Windows, the chat loop uses inline event-driven state machines with `WaitForMultipleObjects`.

Each frame goes over the wire as `[pad_len(1)][frame(512)][random_pad(0-255)]`, so the wire size varies from 513 to 768 bytes. The `pad_len` byte is raw CSPRNG output — uniform random, indistinguishable from ciphertext. This defeats DPI rules that match on fixed byte counts. The low-level helpers (`read_exact`, `write_exact`, `read_exact_dl`, `write_exact_dl`) handle partial reads/writes and deadline enforcement — skip on first reading.

---

## Part 5: Platform Hardening (optional, security auditors)

**Files:** `platform.h/c`

After the TCP connection is established:
- **Phase 1 sandbox**: blocks new connections (no socket/connect/bind)
- **Phase 2 sandbox**: drops setup-only syscalls (no setsockopt after handshake)

Implementation varies by OS:
- Linux: [seccomp](GLOSSARY.md#seccomp-secure-computing-mode)-BPF (kernel-level syscall filter, ~120 lines of BPF bytecode)
- FreeBSD: [Capsicum](GLOSSARY.md#capsicum) (per-fd capability rights)
- OpenBSD: pledge("stdio") + unveil(NULL, NULL)

Also: `mlockall` (prevent key pages from swapping), `RLIMIT_CORE=0` (no crash dumps with keys), `PR_SET_DUMPABLE=0` (block ptrace).

Skip all of this on first reading — the protocol is complete without it.

---

## What to read next

- **PROTOCOL.md** — formal protocol specification with glossary
- **HARDENING.md** — platform-specific security measures
- **nb_io.h/c** — non-blocking I/O for the POSIX chat loop
- **tests/test_p2p.c** — 1036 test assertions covering every code path
- **[Monocypher](GLOSSARY.md#monocypher) documentation** — https://monocypher.org/ (the underlying crypto library)
