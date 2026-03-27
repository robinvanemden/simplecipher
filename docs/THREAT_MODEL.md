# Threat Model and Known Limitations

> **Audience:** Security auditors, high-risk users, and anyone evaluating SimpleCipher's guarantees.

## What SimpleCipher defends against

| Attacker | Protection | Mechanism |
|----------|-----------|-----------|
| Network observer (passive) | Message content confidential | XChaCha20-Poly1305 AEAD, fixed 512-byte frames |
| Network observer (active, MITM) | Detected via SAS verification | Commit-then-reveal handshake, 32-bit SAS |
| Malicious peer (frame injection) | Rejected by MAC | Poly1305 authentication, sequence number check |
| Malicious peer (replay/reorder) | Rejected | Strict sequence equality, chain ratchet |
| Local non-root attacker | Memory protected | PR_SET_DUMPABLE=0, seccomp, Capsicum, pledge |
| Post-compromise of chain key | Healed by DH ratchet (takes effect one message after ratchet step) | Fresh X25519 keypair on direction switch |

## What SimpleCipher does NOT defend against

### Platform limitations (cannot fix in software)

| Limitation | Impact | Affected platforms |
|-----------|--------|-------------------|
| SIGKILL bypasses all cleanup | Key material remains in RAM | All |
| Compiler may spill keys to stack slots that crypto_wipe cannot reach | Key fragments persist on stack | All (inherent to C) |
| Java Strings are immutable — GC doesn't wipe | Message plaintext lingers in JVM heap | Android |
| Root/kernel attacker bypasses PR_SET_DUMPABLE | Full memory read | All (root is omnipotent) |
| Terminal emulator scrollback | May retain chat history (mitigated by alternate screen buffer in TUI, purge_terminal in CLI) | Desktop |

### Design tradeoffs (fixable but at a cost)

| Limitation | Impact | Rationale |
|-----------|--------|-----------|
| No PIE on static musl binaries | No ASLR for code/data segments | musl toolchain lacks rcrt1.o; upgrade pending |
| 32-bit SAS | 1-in-4-billion chance of MITM per session | Commitment scheme prevents brute-force; adequate for interactive verification |
| Protocol fingerprint (33+33+32+32+512 pattern) | Traffic identifiable as SimpleCipher | Fixed frames prevent length leakage; use Tor for anonymity |
| Cover traffic minimum 500ms interval | Frames arriving <500ms apart are distinguishable from cover | Delaying real sends to cover boundaries would add latency |
| No sandbox on Windows/macOS | Code execution vuln has full system access | No portable syscall sandbox API exists |
| mlockall may fail silently | Key material can be swapped to disk | Fails on systems with low RLIMIT_MEMLOCK; warning printed |
| X25519 is not post-quantum | Vulnerable to future quantum computers (Shor's algorithm) | Symmetric layer (BLAKE2b, XChaCha20) provides 128-bit quantum security; X25519 is the single quantum-vulnerable component. Practical quantum threat is 2035-2045 (requires millions of physical qubits). A hybrid X25519 + ML-KEM-768 handshake (following Signal's PQXDH model) will be added when quantum computing advances warrant it. |

### Insider attacks (authenticated malicious peer)

An authenticated peer who completes the handshake legitimately can:

| Attack | Impact | Mitigation |
|--------|--------|-----------|
| Ratchet bombing (FLAG_RATCHET every frame) | CPU exhaustion on low-power devices (~3ms X25519 per frame on RPi Zero) | Session can be terminated with Ctrl+C; rate-limiting is a future option |
| Message flooding (1000 messages) | Overwrites legitimate message history in TUI ring buffer | Ring buffer is fixed-size by design; no persistent storage to protect |
| Steganographic padding | Up to 485 bytes/frame covert channel in authenticated zero-padding | Padding is AEAD-protected; not readable without session keys |
| Session keepalive | Session stays alive indefinitely (no idle timeout) | User can always disconnect; TCP keepalive eventually fires |

### Environmental assumptions

| Assumption | What breaks if wrong | Notes |
|-----------|---------------------|-------|
| OS CSPRNG is unpredictable | Identical ephemeral keys across sessions | Real risk in VM snapshot restore / container checkpoint (CRIU) — kernel entropy pool is duplicated. Not fixable in userspace. getrandom(flags=0) blocks until pool is initialized but does not detect snapshot duplication. |
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
- SAS displayed via write() (not printf) to avoid libc stdio buffer residue

### Verified by
- 649 automated tests (639 core + 10 SOCKS5)
- ASan + UBSan + MSan in CI
- 5 libFuzzer targets (frame_open, sanitize, validate_port, socks5, fingerprint)
- dudect statistical timing tests (ct_compare, is_zero32)
- CI on 8 platforms: Linux/Windows x86_64+aarch64, FreeBSD, OpenBSD (bare-metal)
- Release builds fail-closed on missing bare-metal verification
