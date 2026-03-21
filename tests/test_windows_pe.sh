#!/usr/bin/env bash
# Test Windows PE binary structure without executing it.
# Used for cross-compiled binaries that can't run on the current host.
# Usage: test_windows_pe.sh <binary> <expected-machine-hex> <arch-label>
#   e.g.: test_windows_pe.sh ./simplecipher.exe aa64 aarch64
set -uo pipefail

BIN="${1:?Usage: $0 <binary> <machine-hex> <arch-label>}"
EXPECTED_MACHINE="${2:?Usage: $0 <binary> <machine-hex> <arch-label>}"
ARCH_LABEL="${3:?Usage: $0 <binary> <machine-hex> <arch-label>}"

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

# Read N bytes as hex from offset
hex_at() { xxd -s "$1" -l "$2" -p "$BIN" 2>/dev/null | tr -d '\n'; }

# Read a little-endian 32-bit value as decimal
le32() {
    local h
    h=$(hex_at "$1" 4)
    printf '%d' "0x${h:6:2}${h:4:2}${h:2:2}${h:0:2}"
}

# Read a little-endian 16-bit value as hex
le16() {
    local h
    h=$(hex_at "$1" 2)
    echo "${h:2:2}${h:0:2}"
}

echo "=== PE analysis ($ARCH_LABEL) ==="

check "exists" "test -f '$BIN'"

# MZ header
check "is PE executable (MZ header)" \
    "test \"\$(hex_at 0 2)\" = '4d5a'"

# Read PE offset from 0x3C (4 bytes, little-endian)
PE_OFFSET=$(le32 0x3C)

# PE signature "PE\0\0"
check "PE signature" \
    "test \"\$(hex_at $PE_OFFSET 4)\" = '50450000'"

# Machine type (2 bytes at PE+4, little-endian)
MACHINE=$(le16 $((PE_OFFSET + 4)))
check "architecture is $ARCH_LABEL (0x$EXPECTED_MACHINE)" \
    "test '$MACHINE' = '$EXPECTED_MACHINE'"

# PE32+ magic (0x020B at optional header = PE+24)
OPT_MAGIC=$(le16 $((PE_OFFSET + 24)))
check "is PE32+ (64-bit)" \
    "test '$OPT_MAGIC' = '020b'"

# Stripped (NumberOfSymbols == 0 at PE+12)
NUM_SYMBOLS=$(hex_at $((PE_OFFSET + 12)) 4)
check "is stripped (no symbols)" \
    "test '$NUM_SYMBOLS' = '00000000'"

SIZE="$(stat --format=%s "$BIN" 2>/dev/null || stat -f%z "$BIN" 2>/dev/null || echo 999999)"
check "size < 256KB" "test '$SIZE' -lt 262144"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
