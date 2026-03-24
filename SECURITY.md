# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in SimpleCipher, please report it responsibly.

**Email:** robinvanemden@gmail.com

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Affected versions (or "all")
- Severity assessment if you have one

**What to expect:**
- Acknowledgment within 48 hours
- A fix or mitigation plan within 7 days for critical issues
- Credit in the fix commit (unless you prefer anonymity)

**Please do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Publish details before a fix is available
- Test against other people's live sessions

## Scope

The following are in scope for security reports:

- Protocol flaws (handshake, key derivation, ratchet, frame format)
- Memory safety bugs in `src/` (buffer overflow, use-after-free, etc.)
- Cryptographic misuse (nonce reuse, missing wipe, timing leak)
- Android-specific issues (key leakage, UI bypass, intent injection)
- Build/CI supply chain issues (unsigned releases, toolchain compromise)

The following are out of scope:

- Monocypher library bugs (report to [Monocypher](https://monocypher.org/) directly)
- OS-level attacks (swap forensics, terminal scrollback) — documented as known limitations
- Denial of service via network flooding — SimpleCipher is not a server
- Social engineering (user skips SAS verification)

## Security Testing

SimpleCipher's verification stack is documented in the README. If you're auditing:

- `make test` — 665 unit/integration tests
- `python3 tests/cbmc_harness.py` — CBMC formal verification (57K properties)
- `valgrind --track-origins=yes ./test_timecop` — constant-time verification
- ASan + UBSan + MSan run in CI on every push
- libFuzzer targets in `tests/fuzz_*.c`
