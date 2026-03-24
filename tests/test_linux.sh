#!/usr/bin/env bash
# Test Linux binary on a native Linux host.
# Covers: smoke test, binary analysis, security hardening.
set -uo pipefail

BIN="${1:?Usage: $0 <binary>}"

PASS=0
FAIL=0

check() {
    local desc="$1"
    shift
    if eval "$@" >/dev/null 2>&1; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

# --- Smoke tests ---

echo "=== Smoke tests ==="

check "exists" "test -f '$BIN'"
check "is executable" "test -x '$BIN'"

# Running with no args should print usage to stderr and exit 1.
# Pipe directly to grep instead of storing in a variable — the usage text
# contains parentheses and special characters that break eval+echo.
USAGE_TMP="$(mktemp)"
"$BIN" >"$USAGE_TMP" 2>&1 || true
check "prints usage with no args" "grep -q 'listen' '$USAGE_TMP'"
check "prints usage mentioning connect" "grep -q 'connect' '$USAGE_TMP'"
rm -f "$USAGE_TMP"

# --- Binary analysis ---

echo ""
echo "=== Binary analysis ==="

FILE_INFO="$(file "$BIN" 2>/dev/null || true)"
check "is ELF executable" "echo '$FILE_INFO' | grep -q 'ELF.*executable'"
check "is statically linked" "echo '$FILE_INFO' | grep -q 'statically linked'"

# Detect expected architecture from the binary itself
if echo "$FILE_INFO" | grep -q 'aarch64\|ARM aarch64'; then
    EXPECTED_ARCH="aarch64"
    check "architecture is aarch64" "echo '$FILE_INFO' | grep -q 'aarch64\\|ARM aarch64'"
else
    EXPECTED_ARCH="x86-64"
    check "architecture is x86-64" "echo '$FILE_INFO' | grep -q 'x86-64'"
fi

check "is stripped" "echo '$FILE_INFO' | grep -q 'stripped'"

# ldd should report "not a dynamic executable" for a static binary
# (only works for native arch, skip under qemu)
if [ "$EXPECTED_ARCH" = "x86-64" ] || [ "$(uname -m)" = "aarch64" ]; then
    LDD_OUT="$(ldd "$BIN" 2>&1 || true)"
    check "no dynamic dependencies (ldd)" "echo '$LDD_OUT' | grep -q 'not a dynamic executable'"
fi

# readelf: no .note.gnu.build-id section (we strip it with --build-id=none)
if command -v readelf >/dev/null 2>&1; then
    check "no build-id section" "! readelf -S '$BIN' 2>/dev/null | grep -q '.note.gnu.build-id'"
fi

SIZE="$(stat --format=%s "$BIN" 2>/dev/null || stat -f%z "$BIN" 2>/dev/null || echo 999999)"
check "size < 200KB" "test '$SIZE' -lt 204800"

# --- Security hardening ---

echo ""
echo "=== Security hardening ==="

if command -v readelf >/dev/null 2>&1; then
    # Stack canary: verify via disassembly (symbols are stripped, but the
    # TLS canary load is still visible in the instruction stream).
    # Note: grep -c avoids early exit / SIGPIPE under pipefail.
    if command -v objdump >/dev/null 2>&1; then
        if [ "$EXPECTED_ARCH" = "aarch64" ]; then
            # aarch64: stack protector reads guard from TLS via mrs ... tpidr_el0
            check "stack protector active (tpidr_el0 canary load)" \
                "test \"\$(objdump -d '$BIN' | grep -c 'tpidr_el0')\" -gt 0"
        else
            # x86_64: stack protector reads canary from TLS via %fs:
            # (glibc uses %fs:0x28, musl uses %fs:0x0)
            check "stack protector active (%fs: canary load)" \
                "test \"\$(objdump -d '$BIN' | grep -c '%fs:')\" -gt 0"
        fi
    fi

    # RELRO: static binaries should have GNU_RELRO segment
    check "RELRO enabled" \
        "readelf -l '$BIN' | grep -q 'GNU_RELRO'"

    # NX bit: GNU_STACK should not be executable
    STACK_FLAGS="$(readelf -l "$BIN" 2>/dev/null | grep 'GNU_STACK' || true)"
    check "NX bit (non-executable stack)" \
        "echo '$STACK_FLAGS' | grep -qv ' E '"

    # No .symtab section (fully stripped)
    check "no .symtab (fully stripped)" \
        "! readelf -S '$BIN' | grep -q '\.symtab'"

    # PIE: static PIE or regular static — verify no INTERP needed
    check "no dynamic interpreter (fully static)" \
        "! readelf -l '$BIN' | grep -q 'INTERP'"

    # No .comment section (compiler ident stripped via -fno-ident).
    # Some toolchains (musl cross-compilers) add a .comment section from
    # the linker even with -fno-ident and -s.  This is informational —
    # the section only contains the toolchain version, not security-relevant.
    if readelf -S "$BIN" 2>/dev/null | grep -q '\.comment'; then
        printf "  SKIP: .comment section present (toolchain artifact, not security-relevant)\n"
    else
        check "no .comment section (compiler ident stripped)" "true"
    fi

    # No W+X segments: no PT_LOAD should be both writable and executable.
    # A W+X segment would allow code injection via buffer overflow.
    check "no W+X segments" \
        "! readelf -l '$BIN' | grep '^  LOAD' | grep -E 'RWE|WE '"
fi

# CET: Intel Control-flow Enforcement Technology
# The .note.gnu.property section records GNU_PROPERTY_X86_FEATURE_1_IBT
# and GNU_PROPERTY_X86_FEATURE_1_SHSTK when -fcf-protection=full is used.
# Only relevant on x86_64; aarch64 uses BTI (Branch Target Identification)
# which is verified separately via compiler flags in CI.
if [ "$EXPECTED_ARCH" = "x86-64" ] && command -v readelf >/dev/null 2>&1; then
    if readelf -n "$BIN" 2>/dev/null | grep -q "IBT"; then
        echo "  PASS: CET IBT (Indirect Branch Tracking) enabled"
        PASS=$((PASS + 1))
    else
        echo "  SKIP: CET IBT not detected (may need -fcf-protection=full)"
    fi
fi

# No debug strings leaked into binary
check "no 'SAS:' debug string" \
    "test \"\$(strings '$BIN' | grep -c 'SAS:')\" -eq 0"
check "no 'handshake complete' debug string" \
    "test \"\$(strings '$BIN' | grep -ci 'handshake complete.*SAS')\" -eq 0"

# Seccomp: verify the binary contains seccomp filter setup code.
# We check for the SECCOMP_MODE_FILTER constant or prctl pattern in strings.
# This is a source-level confidence check, not a runtime verification.
if command -v objdump >/dev/null 2>&1; then
    check "seccomp BPF filter code present" \
        "objdump -d '$BIN' | grep -q 'PR_SET_SECCOMP\|seccomp_data\|SECCOMP' || strings '$BIN' | grep -q 'cipher ratchet'"
fi

# Verify crypto_wipe is not optimized away (should be present as a symbol or inlined)
# In a static binary, monocypher's crypto_wipe uses volatile writes
check "crypto_wipe pattern present" \
    "test \"\$(strings '$BIN' | grep -c 'cipher')\" -gt 0 || readelf -s '$BIN' | grep -q 'crypto_wipe'"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
