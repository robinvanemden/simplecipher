# Formal Security Analysis

> **Audience:** Cryptographers, security researchers, and students of provable security.
> This document states SimpleCipher's security properties in formal terms.
> For a plain-English overview, see [PROTOCOL.md](PROTOCOL.md).
> For definitions of terms, see [GLOSSARY.md](GLOSSARY.md).

---

## 1. Notation and conventions

| Symbol | Meaning |
|--------|---------|
| &lambda; | Security parameter. All keys are &lambda; = 256 bits (32 bytes). |
| negl(&lambda;) | A function &mu; such that for every polynomial p, &mu;(&lambda;) < 1/p(&lambda;) for sufficiently large &lambda;. |
| Adv<sup>X</sup><sub>A</sub> | The advantage of adversary A in game X. |
| A &Vert;&Vert; B | Byte concatenation of A and B. |
| {0,1}<sup>n</sup> | The set of n-bit strings. |
| x &larr;$ S | x sampled uniformly at random from set S. |
| BLAKE2b<sub>k</sub>(m) | BLAKE2b with key k and message m, producing a 32-byte output. |
| X25519(a, B) | Scalar multiplication of private scalar a with point B on Curve25519. |

**Game-based syntax.** Security is defined via games between a Challenger C and a probabilistic polynomial-time (PPT) adversary A. The game initialises state, answers oracle queries from A, and outputs a bit. A's advantage is \|Pr[A wins] - 1/2\| (for indistinguishability games) or Pr[A wins] (for unforgeability games). A scheme is secure if the advantage is negl(&lambda;) for all PPT A.

**Constants from the implementation:**

| Constant | Value | Source |
|----------|-------|--------|
| KEY | 32 bytes (256 bits) | `crypto.h` enum |
| NONCE_SZ | 24 bytes (192 bits) | `crypto.h` enum |
| MAC_SZ | 16 bytes (128 bits) | `crypto.h` enum |
| FRAME_SZ | 512 bytes | `protocol.h` enum |
| AD_SZ | 8 bytes (64 bits) | `protocol.h` enum |
| CT_SZ | 488 bytes | FRAME_SZ - AD_SZ - MAC_SZ |
| MAX_MSG | 485 bytes | CT_SZ - 2 - 1 (length field + flags) |
| MAX_MSG_RATCHET | 453 bytes | MAX_MSG - KEY (ratchet pubkey) |
| MAX_AUTH_FAILURES | 3 | `protocol.h` enum |
| PROTOCOL_VERSION | 1 | `protocol.h` enum |
| WIRE_PAD_MAX | 255 bytes | `protocol.h` enum |

---

## 2. Security definitions

### 2.1 IND-CCA2 for the AEAD frame format

**Game IND-CCA2<sub>AEAD</sub>(A):**

1. C generates a random key k &larr;$ {0,1}<sup>256</sup>.
2. A may issue encryption queries Enc(ad, m<sub>0</sub>, m<sub>1</sub>) where |m<sub>0</sub>| = |m<sub>1</sub>|. C picks b &larr;$ {0,1}, computes c = AEAD.Enc(k, nonce, ad, m<sub>b</sub>), returns c.
3. A may issue decryption queries Dec(ad, c') for any c' not previously returned by Enc. C returns AEAD.Dec(k, nonce, ad, c') or &perp;.
4. A outputs b'. A wins if b' = b.

Adv<sup>IND-CCA2</sup><sub>A</sub> = |Pr[b' = b] - 1/2|.

SimpleCipher's frame format achieves IND-CCA2 security under the assumption that XChaCha20-Poly1305 is IND-CCA2 secure (which follows from the PRF security of ChaCha20 and the &epsilon;-almost-&Delta;-universal property of Poly1305).

### 2.2 INT-CTXT for the AEAD frame format

**Game INT-CTXT<sub>AEAD</sub>(A):**

1. C generates k &larr;$ {0,1}<sup>256</sup>.
2. A may issue encryption queries and receives ciphertexts.
3. A outputs (ad*, c*) not previously produced by an encryption query.
4. A wins if AEAD.Dec(k, nonce, ad*, c*) &ne; &perp;.

Adv<sup>INT-CTXT</sup><sub>A</sub> = Pr[A wins].

XChaCha20-Poly1305 provides INT-CTXT security with forgery probability bounded by (q<sub>d</sub> + 1) / 2<sup>128</sup> per key, where q<sub>d</sub> is the number of decryption queries. Since SimpleCipher uses a fresh key per message (via `chain_step`), each key sees exactly one encryption and at most one decryption attempt, making the bound 2<sup>-128</sup> per frame.

### 2.3 Session-key indistinguishability

**Game SK-IND(A):**

1. C runs the handshake honestly: generates ephemeral keypairs for both parties, computes the X25519 shared secret, derives PRK via `domain_hash("cipher x25519 sas root v1", dh || init_pub || resp_pub)`, then derives session keys via `expand`.
2. C picks b &larr;$ {0,1}. If b = 0, C gives A the real session key (root, tx chain, rx chain). If b = 1, C gives A independent random 32-byte strings.
3. A outputs b'.

Adv<sup>SK-IND</sup><sub>A</sub> = |Pr[b' = b] - 1/2|.

**Reduction.** If A distinguishes the real session keys from random with non-negligible advantage, we construct B that breaks either CDH on Curve25519 or the PRF security of BLAKE2b. B embeds the CDH challenge into the handshake public keys; if A succeeds, B either extracts the DH shared secret (breaking CDH) or distinguishes the BLAKE2b-based KDF output from random (breaking PRF security). Therefore:

Adv<sup>SK-IND</sup><sub>A</sub> &le; Adv<sup>CDH</sup><sub>B</sub> + Adv<sup>PRF</sup><sub>B'</sub>(BLAKE2b)

Both terms are negl(&lambda;) under the assumptions stated in Section 3.

---

## 3. Cryptographic assumptions

### 3.1 Computational Diffie-Hellman (CDH) on Curve25519

**Assumption.** For generator G of Curve25519, given (aG, bG) for random scalars a, b &larr;$ Z<sub>p</sub>, computing abG is infeasible for PPT adversaries.

The security of X25519 key exchange reduces to CDH on Curve25519. Bernstein proved Curve25519 provides approximately 128 bits of security against classical adversaries (the best known attack is Pollard's rho with expected cost ~2<sup>126</sup> group operations).

**Reference:** Bernstein, D.J. "Curve25519: new Diffie-Hellman speed records." PKC 2006.

SimpleCipher additionally checks for the all-zero DH output via `is_zero32` (constant-time) to reject small-subgroup/low-order point attacks. If X25519 returns the all-zero point, `session_init` returns -1 and the session is aborted.

### 3.2 PRF security of BLAKE2b in keyed mode

**Assumption.** BLAKE2b<sub>k</sub>(&middot;) for a random 256-bit key k is indistinguishable from a random function {0,1}<sup>*</sup> &rarr; {0,1}<sup>256</sup> for PPT adversaries.

BLAKE2b's compression function is based on ChaCha. The keyed mode uses the key as the initialisation vector, providing PRF security under the assumption that the underlying permutation behaves as a pseudorandom permutation.

SimpleCipher uses keyed BLAKE2b in two constructions:
- `domain_hash(out, label, msg)` = BLAKE2b<sub>label</sub>(msg) -- key is a public domain label
- `expand(out, prk, label)` = BLAKE2b<sub>prk</sub>(label) -- key is a secret pseudo-random key

The first provides domain separation (collision resistance suffices). The second requires PRF security (secret key, adversary sees outputs for different labels).

**Reference:** Aumasson, J.-P., Neves, S., Wilcox-O'Hearn, Z., Winnerlein, C. "BLAKE2: simpler, smaller, fast as MD5." ACNS 2013.

### 3.3 AEAD security of XChaCha20-Poly1305

**Assumption.** XChaCha20-Poly1305 is IND-CCA2 and INT-CTXT secure when used with a unique (key, nonce) pair per encryption.

XChaCha20-Poly1305 combines the ChaCha20 stream cipher (extended to a 192-bit nonce via HChaCha20) with the Poly1305 one-time MAC. Security reduces to:
- ChaCha20 as a PRF (stream cipher security)
- Poly1305 as an &epsilon;-almost-&Delta;-universal hash family (MAC security)

The extended nonce (192 bits) permits safe use with random nonces. SimpleCipher uses a deterministic nonce derived from the sequence number via `make_nonce`, which zero-fills a 24-byte buffer and stores the 64-bit sequence counter in little-endian at the start. Since each message uses a unique key (from `chain_step`), nonce uniqueness is trivially guaranteed even though the nonce construction is deterministic.

**References:**
- Bernstein, D.J. "The Poly1305-AES message-authentication code." FSE 2005.
- Bernstein, D.J. "ChaCha, a variant of Salsa20." 2008.
- Arciszewski, S. "XChaCha20." IETF draft-irtf-cfrg-xchacha-03.

---

## 4. Commitment scheme analysis

### 4.1 Construction

The commitment scheme prevents a man-in-the-middle from adaptively choosing keys after observing the peer's key.

**Commit phase:**
```
commit = make_commit(pub, nonce) = BLAKE2b_keyed("cipher commit v3", pub || nonce)
```
where the key is the ASCII encoding of `"cipher commit v3"` (17 bytes) and the message is the concatenation of the 32-byte X25519 public key and a 32-byte random session nonce (64 bytes total). The nonce is generated fresh each session and binds the commitment to a specific handshake, preventing cross-session replay.

**Reveal phase:** The committer sends `pub` and `nonce` in the clear. The verifier recomputes:
```
expected = BLAKE2b_keyed("cipher commit v3", pub || nonce)
```
and checks `expected == commit` using `crypto_verify32` (constant-time 32-byte comparison). The intermediate `expected` is wiped after comparison.

### 4.2 Security properties

**Binding.** The commitment is binding if an adversary cannot find `(pub, nonce) ≠ (pub', nonce')` such that `make_commit(pub, nonce) = make_commit(pub', nonce')`. This reduces directly to collision resistance of BLAKE2b with a fixed key:

Adv<sup>binding</sup><sub>A</sub> &le; Adv<sup>CR</sup><sub>A</sub>(BLAKE2b<sub>"cipher commit v3"</sub>)

BLAKE2b provides 128 bits of collision resistance (birthday bound on 256-bit output), so:

Adv<sup>binding</sup><sub>A</sub> &le; q<sup>2</sup> / 2<sup>256</sup>

where q is the number of hash evaluations. For any feasible q, this is negl(&lambda;).

**Hiding.** The commitment is computationally hiding if an adversary cannot determine pub from commit without the reveal. Since X25519 public keys are points on Curve25519 (not uniformly random bitstrings), hiding requires that BLAKE2b behaves as a one-way function on the image of `crypto_x25519_public_key`. Under the PRF assumption on BLAKE2b (Section 3.2), the commitment output is indistinguishable from random, which implies hiding. The session nonce adds 256 bits of additional entropy, ensuring identical public keys in different sessions produce unrelated commitments.

### 4.3 SAS security

After commitment and reveal, both parties derive a Short Authentication String (SAS):

```
dh        = X25519(self_priv, peer_pub)
ikm       = dh || init_pub || resp_pub || init_nonce || resp_nonce || version   (161 bytes, canonical order)
prk       = domain_hash("cipher x25519 sas root v1", ikm)
sas_key   = expand(prk, "sas")                  (32 bytes)
SAS       = sas_key[0..3]              (4 bytes, shown as XXXX-XXXX)
```

The SAS output space is 2<sup>32</sup> values. A man-in-the-middle Mallory who intercepts the exchange must choose her fake keys (and commitments) *before* seeing Alice's and Bob's real keys. She cannot adaptively search for a collision after the fact.

**Pr[MITM success] analysis.** Mallory commits to fake keypairs (k<sub>A</sub>', k<sub>B</sub>') before seeing the honest keys (k<sub>A</sub>, k<sub>B</sub>). After reveal, Alice computes SAS from DH(priv<sub>A</sub>, k<sub>A</sub>') and Bob computes SAS from DH(priv<sub>B</sub>, k<sub>B</sub>'). For both SAS values to match, Mallory needs SAS<sub>Alice</sub> = SAS<sub>Bob</sub>. Since Mallory's committed keys are fixed before the honest keys are revealed:

Pr[MITM success] &le; 2<sup>-32</sup> per session

This assumes Mallory cannot predict the honest parties' ephemeral keys (which are generated from the OS CSPRNG) and that the commitment scheme is binding (so Mallory cannot change her keys after committing).

**Temporal ordering.** The diagram below shows why adaptive search is impossible — Mallory must commit before seeing the honest keys:

```
Time   Alice                 Mallory (MITM)              Bob
 |
 |     gen (sk_A, pk_A)      intercepts both sides
 |     commit_A = H(pk_A)
 |        ----- commit_A -------->
 |                            must commit NOW
 |                            (hasn't seen pk_A yet!)
 |                               ---- commit_M1 ----------->
 |                               <--- commit_B ------------ gen (sk_B, pk_B)
 |        <--- commit_M2 --------                           commit_B = H(pk_B)
 |                            (hasn't seen pk_B yet!)
 |
 |     reveal pk_A ---------->
 |                            sees pk_A -- TOO LATE
 |                            to change commit_M1!
 |                               ---- reveal pk_M1 -------->
 |                               <--- reveal pk_B ---------
 |        <--- reveal pk_M2 --
 |
 |     SAS_A = f(sk_A, pk_M2)                    SAS_B = f(sk_B, pk_M1)
 |
 |     SAS_A = SAS_B only if Mallory guessed right (Pr <= 2^-32)
```

Once `commit_M1 = H(pk_M1)` is sent, Mallory cannot find an alternative `pk_M1'` that produces the same commitment without breaking BLAKE2b collision resistance (Section 4.2). Her only strategy is guessing, over the 32-bit SAS output space.

**Why 32 bits is acceptable for interactive verification.** The SAS is verified by a human in real-time over an out-of-band channel (voice/video call). A 2<sup>-32</sup> &asymp; 2.3 &times; 10<sup>-10</sup> probability of success per session is negligible in the interactive setting. The adversary gets exactly one attempt per session (the commitment prevents retry after failure). Even at one session per second sustained for a year, the cumulative probability remains below 10<sup>-2</sup>. For automated/unattended verification where an adversary can attempt many sessions without human oversight, 32 bits is insufficient.

---

## 5. Ratchet security

### 5.1 Symmetric chain ratchet (forward secrecy)

**Construction.** `chain_step` derives two values from the current chain key:

```
mk   = expand(chain, "mk")    = BLAKE2b_keyed(chain, "mk")
next = expand(chain, "chain")  = BLAKE2b_keyed(chain, "chain")
```

The message key `mk` encrypts a single frame via XChaCha20-Poly1305. The chain advances to `next`, and the old `chain` value is overwritten.

**Forward secrecy claim.** For any n > 0, given chain<sub>n</sub> (the chain key after n steps), computing any mk<sub>i</sub> for i < n is infeasible.

**Proof sketch.** Recovery of mk<sub>i</sub> from chain<sub>n</sub> requires inverting at least one application of `expand`, which is BLAKE2b in keyed mode. Under the PRF assumption (Section 3.2), the output of BLAKE2b<sub>chain_i</sub>("chain") is indistinguishable from random, so chain<sub>i+1</sub> reveals no information about chain<sub>i</sub>. By induction over n - i steps, recovery of chain<sub>i</sub> (and therefore mk<sub>i</sub>) from chain<sub>n</sub> requires advantage:

Adv<sup>FS</sup><sub>A</sub> &le; (n - i) &middot; Adv<sup>PRF</sup><sub>B</sub>(BLAKE2b)

which is negl(&lambda;) for polynomial n.

**Key erasure.** The implementation overwrites `s->tx` (or `s->rx`) with the `next_chain` value after a successful send (or receive). The old chain key exists only in stack variables that are explicitly wiped via `crypto_wipe`. Message keys `mk` are similarly wiped after each `crypto_aead_lock` / `crypto_aead_unlock` call.

### 5.2 DH ratchet (post-compromise security)

**Construction.** When the conversation direction switches, `ratchet_prepare` (called eagerly from `frame_open` at receive time) pre-computes the next DH ratchet step. The results are staged in session memory and committed by `ratchet_send` at the next `frame_build`. The computation is:

```
dh_priv', dh_pub' = fresh X25519 keypair       (from OS CSPRNG)
dh_secret         = X25519(dh_priv', peer_dh)
ikm               = root || dh_secret           (64 bytes)
root'             = domain_hash("cipher ratchet v2", ikm)
tx'               = expand(root', "chain")
```

The sender includes `dh_pub'` in the frame (FLAG_RATCHET set). The receiver performs the mirror operation in `ratchet_receive`:

```
dh_secret         = X25519(dh_priv, peer_new_pub)
ikm               = root || dh_secret           (64 bytes)
root'             = domain_hash("cipher ratchet v2", ikm)
rx'               = expand(root', "chain")
```

**Post-compromise security claim.** If an adversary compromises all session state (root, tx, rx, dh_priv, staged_*) at time t, then after one DH round-trip (one send from each party) *with no further compromise*, the adversary can no longer derive session keys.

**Note on eager pre-computation.** Because `ratchet_prepare` runs at receive time (not send time), the fresh keypair and derived chain exist in `staged_*` fields from the moment a frame is received until the next send commits them. A RAM compromise during this window recovers the staged private key and the next outbound chain. The practical PCS recovery window is therefore: one receive (which creates the staged state) followed by one send (which commits and wipes it), with no compromise in between.

**Proof sketch.** After compromise at time t, the next `ratchet_prepare` generates dh_priv' &larr;$ {0,1}<sup>256</sup> from the OS CSPRNG. The adversary does not know dh_priv' (assuming CSPRNG security and no further RAM access). The new root key depends on X25519(dh_priv', peer_dh), which the adversary cannot compute without dh_priv'. Under CDH:

Adv<sup>PCS</sup><sub>A</sub> &le; Adv<sup>CDH</sup><sub>B</sub>(Curve25519) + Adv<sup>PRF</sup><sub>B'</sub>(BLAKE2b)

After the peer also performs a ratchet step (generating their own fresh keypair), the root key has been mixed with two independent DH secrets unknown to the adversary. Recovery of any subsequent chain key requires breaking CDH or the PRF.

**Recovery timing.** The ratchet key is included in a frame encrypted under the *pre-ratchet* chain (the old `tx` chain is saved before `ratchet_send` overwrites it). The receiver processes the ratchet key after decrypting that frame. Therefore, the first frame after a ratchet step is encrypted under the old chain; recovery takes effect from the *second* frame onward (the first frame encrypted under the new chain derived from the ratchet).

### 5.3 Transactional receive

`ratchet_receive` stages all derived values in local variables (`staged_root`, `staged_rx`) before committing to session state. If the X25519 output is all-zero (indicating a malicious low-order point), the function returns -1 and no session state is mutated. All intermediates (`dh`, `ikm`, `staged_root`, `staged_rx`) are wiped regardless of the outcome.

This ensures atomicity: either the full ratchet step succeeds and all state is updated consistently, or the session state remains unchanged and subsequent legitimate frames can still be processed.

---

## 6. Frame format security

### 6.1 Nonce uniqueness

The nonce for each frame is constructed by `make_nonce(nonce, seq)`:

```
nonce = [seq as little-endian uint64] || [0x00 * 16]
```

where `seq` is a monotonically increasing 64-bit counter (starting at 0, incremented after each successful send or receive). Since each frame also uses a unique message key derived from `chain_step`, the (key, nonce) pair is unique even though the nonce space is not fully utilised. The nonce construction is deterministic and does not consume randomness.

### 6.2 AEAD encryption

Each frame is encrypted via `crypto_aead_lock` (XChaCha20-Poly1305):

- **Key:** mk (32 bytes), a one-time key from `chain_step`
- **Nonce:** 24 bytes from `make_nonce(seq)`
- **Associated data (AD):** the 8-byte sequence number (little-endian `seq`), stored in the first 8 bytes of the frame
- **Plaintext:** the 488-byte plaintext slot (flags + optional ratchet key + length + message + zero padding)
- **Output:** 488 bytes ciphertext + 16 bytes MAC

The AD binds the sequence number to the ciphertext cryptographically. Modifying the sequence number in the clear will cause MAC verification to fail.

### 6.3 Replay and reorder rejection

`frame_open` checks `seq == s->rx_seq` before any cryptographic operations. If the frame's sequence number does not match the expected counter, the frame is rejected immediately. This provides:

- **Replay rejection:** A replayed frame has a sequence number that has already been consumed (seq < rx_seq), so the equality check fails.
- **Reorder rejection:** An out-of-order frame has seq &ne; rx_seq, so it is rejected.

The check is performed before `chain_step` or `crypto_aead_unlock`, so rejected frames incur no cryptographic cost and do not advance the chain.

**Sequence number overflow rejection.** Both `frame_build` and `frame_open` check for `seq == UINT64_MAX` before incrementing and reject the frame if the counter would wrap. This prevents nonce reuse after 2<sup>64</sup> frames (an astronomically large number, but the check ensures correctness even under adversarial conditions).

**Limitation:** This strict ordering means SimpleCipher does not tolerate packet reordering. This is acceptable because the protocol runs over TCP, which guarantees in-order delivery.

### 6.4 Tamper detection

The Poly1305 MAC is verified inside `crypto_aead_unlock` before any plaintext is returned. If verification fails, the function returns non-zero and `frame_open` wipes all intermediates and returns -1. No plaintext from a tampered frame is ever exposed to the caller.

After successful MAC verification, the plaintext slot is parsed: flags are checked (reserved bits must be zero), the length field is validated against the maximum payload size, and only then is session state updated.

### 6.5 Fixed-size framing and wire padding

All frames are exactly FRAME_SZ = 512 bytes regardless of message length. The plaintext slot is zero-padded to CT_SZ = 488 bytes before encryption. This prevents message-length leakage through ciphertext size.

On the wire, each frame is wrapped:

```
[ pad_len : 1 byte ] [ frame : 512 bytes ] [ random_pad : pad_len bytes ]
```

`pad_len` is a raw CSPRNG byte (uniform over [0, 255]). The random padding bytes are also CSPRNG output. Total wire size varies uniformly from 513 to 768 bytes, preventing fixed-size fingerprinting by deep packet inspection.

---

## 7. Known limitations (formally stated)

### 7.1 MAC failure tolerance

MAX_AUTH_FAILURES = 3. An active network attacker can inject up to 3 forged frames (which will fail MAC verification) before the session is torn down. `frame_open` does not mutate session state on MAC failure (chain keys, sequence counters, and root key are untouched), so legitimate frames interleaved with forgeries are processed correctly. The counter resets to 0 on each successful frame.

**Implication:** An attacker who can inject frames into the TCP stream can force session termination by sending 3 consecutive forged frames during an idle period. This is a denial-of-service vector, not a confidentiality or integrity breach.

### 7.2 No post-quantum security

The handshake and DH ratchet rely on CDH on Curve25519. Shor's algorithm running on a sufficiently powerful quantum computer solves the discrete logarithm problem on elliptic curves in polynomial time, breaking both:

- Session key agreement (X25519 in `session_init`)
- Post-compromise security (X25519 in `ratchet_step`)

The symmetric primitives (BLAKE2b, XChaCha20-Poly1305) retain approximately &lambda;/2 = 128 bits of security against Grover's algorithm, which is sufficient. However, the asymmetric components provide zero post-quantum security.

A harvest-now-decrypt-later adversary who records ciphertext today can decrypt it if and when a cryptographically relevant quantum computer becomes available.

### 7.3 No deniability

The commitment scheme is binding: both parties can prove that a specific public key was committed to and revealed during the handshake. A transcript of (commit, pub, SAS) constitutes a non-repudiable proof that the key exchange occurred with that specific key.

In contrast, protocols like OTR provide deniability through MAC key revelation. SimpleCipher does not reveal MAC keys or use any deniability mechanism.

### 7.4 SAS entropy

The SAS is 32 bits (4 bytes of `sas_key`, displayed as `XXXX-XXXX` in hexadecimal). This provides:

- Pr[random collision] = 2<sup>-32</sup> &asymp; 2.3 &times; 10<sup>-10</sup>
- Adequate for single interactive verification (human compares codes via voice/video)
- Inadequate for automated/unattended verification or scenarios where an adversary can attempt many sessions

For additional assurance, SimpleCipher supports optional fingerprint verification (64-bit fingerprint derived via `domain_hash("cipher fingerprint v2", pub)`, formatted as `XXXX-XXXX-XXXX-XXXX`). Combined with SAS, this yields 96 bits of verification entropy.

### 7.5 Cover traffic

SimpleCipher's cover traffic uses the **queue-on-tick** design: real messages are never sent immediately. Instead, they are queued and transmitted on the next cover tick, replacing the cover payload. This ensures every outgoing frame — real or dummy — follows the same CSPRNG-randomized timing distribution. Cover frames are empty messages (zero-length payload) that are indistinguishable from real messages after encryption (same FRAME_SZ = 512 bytes, same wire padding).

Inter-frame intervals are drawn from a **clamped exponential distribution** (mean 500 ms, clamped to [50, 1500] ms), generated by `cover_delay_ms` using the OS CSPRNG. Exponential inter-arrivals mimic natural Poisson traffic patterns (coefficient of variation ≈ 1.0), making the cover stream significantly harder to fingerprint than a uniform or near-constant interval would be.

**Security property:** Because the single send point is the cover tick handler, a network observer cannot distinguish real-message frames from cover frames by timing alone. The inter-frame intervals are identically distributed regardless of user activity.

**Formal limitations:**

- Session start/end times are visible
- Total session duration and frame count are observable
- Rapid-fire messages (faster than the tick rate) queue and serialize, introducing observable delivery delay if message rate exceeds ~2 msg/sec average
- The exponential distribution approximates natural traffic but is not a perfect model of any specific application's traffic pattern; a sufficiently sophisticated classifier may still identify the stream
- **Protocol fingerprinting is not defeated.** The fixed 512-byte inner frame (`FRAME_SZ`) and cleartext `pad_len` byte (uniform random 0-255) create a recognizable wire signature: total sizes between 513-768 bytes with a fixed inner structure. A DPI system that looks beyond timing — at frame sizes, pad_len distribution, or the constant inner frame offset — can identify SimpleCipher traffic regardless of cover traffic timing

Cover traffic provides strong timing-analysis resistance for interactive chat but does not eliminate all metadata leakage. It mitigates *when* you type, not *that* you are using SimpleCipher.

### 7.6 No PIE on static musl binaries

Static binaries linked with musl libc are not compiled as Position-Independent Executables (PIE). This means the main executable is loaded at a fixed address, reducing the effectiveness of Address Space Layout Randomisation (ASLR). Shared libraries (if any were loaded) and the stack/heap are still randomised by the kernel, but the .text and .data segments of the main binary are at predictable addresses.

**Implication:** An adversary with a memory corruption primitive has a known code gadget base, reducing the difficulty of return-oriented programming (ROP) attacks. This is mitigated by the syscall sandbox (seccomp/Capsicum/pledge), which restricts the available attack surface even if code execution is achieved.

---

## 8. References

1. Perrin, T. and Marlinspike, M. "The Double Ratchet Algorithm." Signal Foundation, 2016. https://signal.org/docs/specifications/doubleratchet/

2. Bernstein, D.J. "Curve25519: new Diffie-Hellman speed records." In *Public Key Cryptography -- PKC 2006*, LNCS 3958, pp. 207-228. Springer, 2006.

3. Aumasson, J.-P., Neves, S., Wilcox-O'Hearn, Z., and Winnerlein, C. "BLAKE2: simpler, smaller, fast as MD5." In *Applied Cryptography and Network Security -- ACNS 2013*, LNCS 7954, pp. 119-135. Springer, 2013.

4. Bernstein, D.J. "The Poly1305-AES message-authentication code." In *Fast Software Encryption -- FSE 2005*, LNCS 3557, pp. 32-49. Springer, 2005.

5. Bernstein, D.J. "ChaCha, a variant of Salsa20." Workshop Record of SASC 2008, 2008.

6. Monocypher Quality Assurance and Audit Report. https://monocypher.org/quality-assurance/audit

7. Cohn-Gordon, K., Cremers, C., Dowling, B., Garratt, L., and Stebila, D. "A Formal Security Analysis of the Signal Messaging Protocol." In *IEEE European Symposium on Security and Privacy (EuroS&P)*, 2017.

8. Arciszewski, S. "XChaCha20." IETF Internet-Draft, draft-irtf-cfrg-xchacha-03, 2020.
