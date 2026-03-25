# Assurance Map — SimpleCipher

> **Audience:** Security auditors, students, and anyone who wants to verify that each security claim is backed by code and tests.

Every security property claimed in the README and PROTOCOL.md is listed here with the exact code that implements it and the exact test that verifies it. If a claim has no test, it is noted.

## Cryptographic properties

| Claim | Code | Test | Notes |
|-------|------|------|-------|
| **Confidentiality** (XChaCha20-Poly1305) | `protocol.c:frame_build()`, `protocol.c:frame_open()` | `test_p2p.c:test_crypto_basics` (encrypt/decrypt roundtrip), `test_constant_time.c:frame_build` (timing) | Monocypher handles AEAD |
| **Key agreement** (X25519 ECDH) | `crypto.c:gen_keypair()`, `protocol.c:session_init()` | `test_p2p.c:test_crypto_basics` (DH shared secrets match) | Monocypher handles X25519 |
| **Forward secrecy** (chain ratchet) | `crypto.c:chain_step()` | `test_p2p.c:test_forward_secrecy_key_erasure`, `test_p2p.c:test_sequential_chain_advancement` | Old chain key wiped after each step |
| **Post-compromise security** (DH ratchet) | `ratchet.c:ratchet_init/step_send/step_recv()` | `test_p2p.c:test_dh_ratchet_pcs`, `test_p2p.c:test_dh_ratchet_deep_pcs` | Fresh DH on each direction switch |
| **Integrity** (Poly1305 MAC) | `protocol.c:frame_open()` rejects on MAC failure | `test_p2p.c:test_crypto_basics` (tampered frame rejected) | |
| **Replay rejection** (sequence numbers) | `protocol.c:frame_open()` checks `rx_seq` | `test_p2p.c:test_crypto_basics` (replayed frame rejected), `test_p2p.c:test_dh_ratchet_replay_rejection` | |
| **Commitment scheme** (anti-MITM) | `crypto.c:make_commit()`, `crypto.c:verify_commit()` | `test_p2p.c:test_crypto_basics` (commit verifies/rejects), `test_p2p.c:test_commitment_specificity` | Constant-time via `crypto_verify32` |
| **SAS verification** (32-bit) | `crypto.c:format_sas()` | `test_p2p.c:test_crypto_basics` (SAS format), `test_p2p.c:test_format_sas_edge_cases` | |
| **Fingerprint verification** (64-bit) | `crypto.c:format_fingerprint()`, `crypto.c:ct_compare()` | `test_p2p.c:test_format_fingerprint`, `test_p2p.c:test_fingerprint_roundtrip`, `test_p2p.c:test_fingerprint_handshake_verification` (Tests D-G) | |
| **Message-length hiding** (512-byte frames) | `protocol.h:FRAME_SZ=512`, `protocol.c:frame_build()` | `test_p2p.c:test_frame_boundary_message_sizes` | All frames same size |

## Key lifecycle (wipe guarantees)

| Claim | Code | Test |
|-------|------|------|
| Private key wiped after session_init | `main.c:511`, `jni_bridge.c:647` | `test_p2p.c:test_session_init_wipes_intermediates` |
| Chain key wiped after each message | `crypto.c:chain_step()` overwrites | `test_p2p.c:test_chain_step_wipes_safe` |
| Session state wiped on exit | `protocol.c:session_wipe()` | `test_p2p.c:test_session_wipe`, `test_p2p.c:test_global_session_wipe` |
| Frame build wipes intermediates | `protocol.c:frame_build()` | `test_p2p.c:test_frame_build_wipes_intermediates` |
| Frame open wipes on MAC failure | `protocol.c:frame_open()` | `test_p2p.c:test_frame_open_wipes_on_mac_failure` |
| Fingerprint hash wiped after use | `crypto.c:format_fingerprint()` | `test_p2p.c:test_fingerprint_wipe` |
| Android prekey wiped on all exit paths | `jni_bridge.c:cleanup`, `jni_bridge.c:cleanup_keys` | Code review (JNI-only, not unit-testable) |

## Constant-time operations

| Function | Valgrind (timecop) | Hardware (dudect) |
|----------|--------------------|-------------------|
| `is_zero32` | `test_timecop.c` | `test_constant_time.c` case 0 |
| `verify_commit` | `test_timecop.c` | `test_constant_time.c` case 1 |
| `domain_hash` | `test_timecop.c` | `test_constant_time.c` case 2 |
| `expand` | `test_timecop.c` | `test_constant_time.c` case 3 |
| `chain_step` | `test_timecop.c` | `test_constant_time.c` case 4 |
| `crypto_x25519` | `test_timecop.c` | `test_constant_time.c` case 5 |
| `frame_build` | `test_timecop.c` | `test_constant_time.c` case 6 |
| `ct_compare` | `test_timecop.c` | `test_constant_time.c` case 8 |
| `frame_open` | Not tested (intentional early exit) | `test_constant_time.c` case 7 (known-accept) |

## Platform hardening

| Claim | Code | Test |
|-------|------|------|
| Static binary, zero deps | `CMakeLists.txt` static linking flags | `ci.yml:test-linux` (runs on bare runner) |
| ASLR + DEP (Windows) | `CMakeLists.txt:81` `--dynamicbase --nxcompat --high-entropy-va` | `test_windows.ps1:87` (PE header check) |
| Full RELRO (Linux) | `CMakeLists.txt` `-Wl,-z,relro,-z,now` | `ci.yml:test-linux` (readelf check) |
| Stack canary | `-fstack-protector-strong` | `test_android.sh` (readelf `__stack_chk_fail`) |
| FORTIFY_SOURCE | `-D_FORTIFY_SOURCE=2` | `test_android.sh` (`_chk` functions in .so) |
| Seccomp sandbox phase 1 (Linux) | `platform.c:sandbox_phase1()` — after TCP connection, before handshake. Blocks socket/connect/bind/listen/accept. | `test_p2p.c:test_harden_codepath` — forks child, enters sandbox, verifies `socket()` triggers SIGSYS kill. Source-level check (`test_linux.sh`). |
| Seccomp sandbox phase 2 (Linux) | `platform.c:sandbox_phase2()` — after handshake, before chat loop. Tightened from phase 1: drops setup-only syscalls (select, nanosleep, prctl, mlock, fcntl, setrlimit, etc.) that are no longer needed during chat. | Source-level check (`test_linux.sh`). Phase 2 tightens phase 1; phase 1 enforcement is functionally tested. |
| Capsicum sandbox (FreeBSD) | `platform.c:capsicum_phase1()` — `cap_enter()` + per-fd rights; `capsicum_phase2()` — narrows socket rights. | `test_p2p.c:test_harden_codepath` — forks child, enters capability mode, verifies `open()` returns ENOTCAPABLE. CI-verified on bare-metal FreeBSD 14.3 (Vultr via SSH). |
| OpenBSD pledge/unveil | `platform.c:sandbox_phase1()` (`"stdio"`), `sandbox_phase2()` (`"stdio"`) | `test_p2p.c:test_harden_codepath` — forks child, calls `pledge("stdio")`, verifies `socket()` triggers SIGABRT. CI-verified on bare-metal OpenBSD 7.7 (Vultr via SSH). |
| `mlockall` (Linux) | `platform.c:harden_process()` | `test_p2p.c:test_harden_codepath` |
| Anti-ptrace (Android) | `jni_bridge.c:JNI_OnLoad` `PR_SET_DUMPABLE=0` | `test_android.sh` (grep source) |
| No core dumps (Android) | `jni_bridge.c:JNI_OnLoad` `RLIMIT_CORE=0` | `test_android.sh` (grep source) |
| Symbol visibility (Android) | `jni_exports.map`, `-fvisibility=hidden` | `test_android.sh` (no internal symbols exported) |
| PAC+BTI (ARM64) | `CMakeLists.txt` `-mbranch-protection=standard` | `test_android.sh` (grep CMakeLists) |
| Screenshot blocking (Android) | `MainActivity.java`, `ChatActivity.java` `FLAG_SECURE` | `test_android.sh` (grep source) |
| No log output in release | `jni_bridge.c` `NDEBUG` suppresses `LOGI`/`LOGE` | `test_android.sh` (no log strings in .so) |

## Fuzzing coverage

| Target | File | What it finds |
|--------|------|---------------|
| `frame_open` | `fuzz_frame_open.c` | Buffer overflows in frame parsing |
| `sanitize_peer_text` | `fuzz_sanitize.c` | Crashes on malicious peer messages |
| `validate_port` | `fuzz_validate_port.c` | Integer parsing bugs |
| `socks5_build_request` | `fuzz_socks5.c` | SOCKS5 protocol builder bugs |
| `parse_fingerprint` | `fuzz_fingerprint.c` | Fingerprint parser bugs, round-trip consistency |

## Formal verification

| Property | Tool | Harness |
|----------|------|---------|
| 57,000+ properties (bounds, overflow, pointer safety) | CBMC | `tests/cbmc_harness.py` |

## Known gaps (documented, not bugs)

| Gap | Why | Where documented |
|-----|-----|------------------|
| Android JVM memory hygiene | Java Strings can't be wiped deterministically | `ANDROID.md:What the app cannot guarantee` |
| Android SOCKS5 is connect-mode only | Listen mode requires Tor onion service (root/daemon), not practical on Android | `ANDROID.md:SOCKS5 / Tor support` |
| Clipboard on API 28-29 | Background apps can read clipboard on older Android | `ANDROID.md:Security measures`, app warns user |
| Terminal scrollback may retain messages | OS-level, outside app control | `PROTOCOL.md:What it does NOT provide` |
| Syscall sandbox is Linux/FreeBSD/OpenBSD only | Seccomp (Linux), Capsicum (FreeBSD), pledge (OpenBSD). No equivalent on Windows/macOS | `HARDENING.md` platform table |
| No cross-session recovery | Ephemeral by design | `PROTOCOL.md:What it does NOT provide` |
