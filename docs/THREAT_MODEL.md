# Threat Model and Known Limitations

> **Audience:** Security auditors, high-risk users, and anyone evaluating SimpleCipher's guarantees.

> Every security tool has limits. This document honestly states what SimpleCipher protects against, what it doesn't, and why. **If you're evaluating whether SimpleCipher is right for your situation**, start here. For definitions of technical terms, see the [Glossary](GLOSSARY.md).

## What SimpleCipher defends against

| Attacker | Protection | Mechanism |
|----------|-----------|-----------|
| Network observer (passive) | Message content confidential | XChaCha20-Poly1305 AEAD, fixed 512-byte frames |
| Network observer (active, [MITM](GLOSSARY.md#man-in-the-middle-mitm)) | Detected via [SAS](GLOSSARY.md#sas-short-authentication-string) verification | Commit-then-reveal handshake, 32-bit SAS |
| Malicious peer (frame injection) | Rejected by MAC | Poly1305 authentication, sequence number check |
| Malicious peer (replay/reorder) | Rejected | Strict sequence equality, chain ratchet |
| Local non-root attacker | Memory protected | PR_SET_DUMPABLE=0, [seccomp](GLOSSARY.md#seccomp-secure-computing-mode), [Capsicum](GLOSSARY.md#capsicum), [pledge](GLOSSARY.md#pledge--unveil) |
| Post-compromise of chain key | Healed by DH ratchet (takes effect one message after ratchet step) | Fresh [X25519](GLOSSARY.md#x25519) keypair on direction switch |

## What SimpleCipher does NOT defend against

### Platform limitations (cannot fix in software)

| Limitation | Impact | Affected platforms |
|-----------|--------|-------------------|
| SIGKILL bypasses all cleanup | Key material remains in RAM | All |
| Compiler may spill keys to stack slots that crypto_wipe cannot reach | Key fragments persist on stack | All (inherent to C) |
| Java Strings are immutable — GC doesn't wipe | Message plaintext lingers in JVM heap | Android |
| Root/kernel attacker bypasses PR_SET_DUMPABLE | Full memory read | All (root is omnipotent) |
| Terminal emulator scrollback | May retain chat history (mitigated by alternate screen buffer in TUI, purge_terminal in CLI) | Desktop |
| Malicious accessibility service | Can read all on-screen text (SAS, chat, fingerprint). FLAG_SECURE does not block accessibility. Blocking accessibility would break screen readers for visually impaired users. | Android |

### Design tradeoffs (fixable but at a cost)

| Limitation | Impact | Rationale |
|-----------|--------|-----------|
| No [PIE](GLOSSARY.md#pie-position-independent-executable) on static musl binaries | No [ASLR](GLOSSARY.md#aslr-address-space-layout-randomization) for code/data segments | musl toolchain lacks rcrt1.o; upgrade pending |
| 32-bit SAS | 1-in-4-billion chance of MITM per session | Commitment scheme prevents brute-force; adequate for interactive verification |
| Protocol fingerprint | All wire messages — including handshake rounds — use the same `[pad_len(1)][body(512)][random_pad(0-255)]` format, producing 513-768 bytes per message. Handshake payloads are zero-padded to 512 bytes before wrapping, so DPI cannot distinguish handshake from chat by size. The fixed 512-byte inner body and the cleartext pad_len byte remain distinguishing features for a sophisticated observer. | Uniform wire sizes across all protocol phases. Use `--socks5` with Tor for metadata protection. |
| Cover traffic minimum 500ms interval | Frames arriving <500ms apart are distinguishable from cover | Delaying real sends to cover boundaries would add latency |
| DNS resolution outside connect timeout | The 15-second non-blocking connect timeout does not cover `getaddrinfo()`, which runs before the timed loop. A hostname-based SOCKS5 proxy can stall pre-auth connect well past the stated bound via DNS delays. Multiple resolved addresses multiply the per-candidate 15-second wait. | Use numeric IP addresses for SOCKS5 proxies (localhost `127.0.0.1`); `connect_socket_numeric` enforces `AI_NUMERICHOST` for peer connections |
| Listen mode single-slot | `listen_socket` accepts exactly one TCP peer and closes the listener. Any reachable host can grab the only slot before the intended peer connects, forcing a restart. | SimpleCipher is a 1:1 chat tool, not a server. Use Tor onion services or firewall rules to restrict inbound access; re-run on failure |
| No sandbox on Windows | Code execution vuln has full system access on Windows | Windows has no equivalent to seccomp/Capsicum/pledge; process mitigation policies provide partial defense |
| mlockall may fail silently | Key material can be swapped to disk | Fails on systems with low RLIMIT_MEMLOCK; warning printed |
| Public key sent cleartext in handshake round 2 | When using `--identity`, the same public key is sent in every session. A passive network observer can correlate sessions to the same user by matching the 32-byte key in round 2. | Use Tor (`--socks5`) to prevent network observers from seeing handshake content. With `.onion` addresses, no observer sees the cleartext key. Without Tor, the public key (and thus fingerprint) is visible to every network hop. |
| Version byte in commitment | The version byte is bound into the commitment hash `H(pub\|\|nonce\|\|version)`, preventing a MITM from downgrading the protocol version without detection. | Commitment verification fails if the version byte is tampered with. |
| X25519 is not post-quantum | Vulnerable to future quantum computers (Shor's algorithm) | Symmetric layer (BLAKE2b, XChaCha20) provides 128-bit quantum security; X25519 is the single quantum-vulnerable component. Practical quantum threat is 2035-2045 (requires millions of physical qubits). A hybrid X25519 + ML-KEM-768 handshake (following Signal's PQXDH model) will be added when quantum computing advances warrant it. |

### Insider attacks (authenticated malicious peer)

An authenticated peer who completes the handshake legitimately can:

| Attack | Impact | Mitigation |
|--------|--------|-----------|
| Ratchet bombing (FLAG_RATCHET every frame) or high-rate ordinary frames | CPU exhaustion on low-power devices (~3ms X25519 per frame on RPi Zero). Note: eager ratchet pre-computation (`ratchet_prepare`) runs after every accepted frame, not just FLAG_RATCHET frames — any valid inbound frame triggers X25519 work until the local side sends once | All platforms rate-limit incoming frames at 50/sec, dropping excess frames before AEAD decryption + X25519 work; session can be terminated with Ctrl+C |
| Message flooding (1000 messages) | Overwrites legitimate message history in TUI ring buffer; Android could grow handler queue | Ring buffer is fixed-size (desktop); Android rate-limits incoming frames at 50/sec before decryption and caps chatLog at ~100KB |
| Byte-dribble stall | A peer that dribbles bytes or stops reading outbound data can delay I/O completion | All platforms use non-blocking I/O with incremental accumulation (poll + POLLOUT). POSIX loops use `nb_try_recv`/`nb_try_send` with monotonic deadline checks; Windows uses event-driven state machines. Maximum stall before the deadline fires is FRAME_TIMEOUT_S (30 seconds). Ctrl+C stays responsive at all times |
| Steganographic padding | Up to 485 bytes/frame covert channel in authenticated zero-padding | Padding is AEAD-protected; not readable without session keys |
| System message spoofing | A peer can send text like "[peer disconnected]" or "[session error]" to trick the user into thinking the session ended. Only printable ASCII (0x20-0x7E) passes sanitization — newlines, tabs, and control characters are replaced with '.' | Every peer message is prefixed with the `peer:` label (CLI) or displayed in a distinct color (TUI). The mandatory prefix and newline sanitization prevent multi-line spoofs that could hide the `peer:` label. |
| Session keepalive | Session stays alive indefinitely (no idle timeout) | User can always disconnect; TCP keepalive eventually fires |

### Environmental assumptions

| Assumption | What breaks if wrong | Notes |
|-----------|---------------------|-------|
| OS CSPRNG is unpredictable | Identical [ephemeral](GLOSSARY.md#ephemeral) keys across sessions | Real risk in VM snapshot restore / container checkpoint (CRIU) — kernel entropy pool is duplicated. Not fixable in userspace. getrandom(flags=0) blocks until pool is initialized but does not detect snapshot duplication. |
| Out-of-band channel has integrity | MITM goes undetected despite SAS | The OOB channel (phone call, in-person) must resist active tampering. Deepfake voice synthesis is an emerging threat to phone-based SAS comparison. Paper exchange is the strongest method. |
| BLAKE2b is collision-resistant | Commitment scheme breaks, SAS brute-forceable | Standard cryptographic assumption. BLAKE2b has 10+ years of analysis with no practical attacks. |
| TCP delivers bytes in order | Protocol relies on TCP stream semantics | Transparent proxies (Tor, corporate MITM) preserve this. The protocol survives any RFC-compliant TCP stack. |

## Hardening applied

### Compile-time
- `-fstack-protector-strong`, `-ftrivial-auto-var-init=zero`
- `-fvisibility=hidden`, `-fno-delete-null-pointer-checks`
- `-D_FORTIFY_SOURCE=3` (glibc only; musl ignores)
- Full RELRO, NX stack, no lazy binding

### Runtime
- `harden()` called BEFORE any key material exists (mlockall, RLIMIT_CORE=0, PR_SET_DUMPABLE=0)
- Two-phase seccomp-BPF (Linux), Capsicum (FreeBSD), pledge+unveil (OpenBSD)
- TIOCSTI ioctl explicitly blocked in seccomp filter
- Alternate screen buffer (TUI) erases chat on exit
- All sensitive buffers wiped via Monocypher's volatile-based crypto_wipe
  (including SOCKS5 target hostname on all code paths, pipe command buffers, local IP strings)
- SAS displayed via write() (not printf) to avoid libc stdio buffer residue
- SAS verification monitors peer socket for disconnect (POLLHUP/FD_CLOSE)
  and enforces a 5-minute timeout on all platforms
- listen_socket_cb uses poll() instead of select() on POSIX to prevent
  FD_SET overflow when fd >= FD_SETSIZE (1024)

### Verified by
- 1062 automated tests (1036 P2P + 10 SOCKS5 + 16 CLI flag integration)
- ASan + UBSan + MSan in CI
- 6 libFuzzer targets (frame_open, sanitize, validate_port, socks5, fingerprint, identity_load)
- dudect statistical timing tests (ct_compare, is_zero32)
- CI on 6 platform/arch combinations: Linux x86_64+aarch64, Windows x86_64+aarch64, FreeBSD, OpenBSD (bare-metal)
- Release builds fail-closed on missing bare-metal verification
