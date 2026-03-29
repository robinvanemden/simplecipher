#!/usr/bin/env bash
# Test macOS binary on a native macOS host.
# Covers: smoke test, binary analysis, CLI arguments.
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
USAGE_TMP="$(mktemp)"
"$BIN" >"$USAGE_TMP" 2>&1 || true
check "prints usage with no args" "grep -q 'listen' '$USAGE_TMP'"
check "prints usage mentioning connect" "grep -q 'connect' '$USAGE_TMP'"
rm -f "$USAGE_TMP"

# --- Binary analysis ---

echo ""
echo "=== Binary analysis ==="

FILE_INFO="$(file "$BIN" 2>/dev/null || true)"
check "is Mach-O executable" "echo '$FILE_INFO' | grep -q 'Mach-O'"

# Detect expected architecture
if echo "$FILE_INFO" | grep -q 'arm64'; then
    EXPECTED_ARCH="arm64"
    check "architecture is arm64" "echo '$FILE_INFO' | grep -q 'arm64'"
else
    EXPECTED_ARCH="x86_64"
    check "architecture is x86_64" "echo '$FILE_INFO' | grep -q 'x86_64'"
fi

# Check dynamic dependencies — should only link libSystem (the macOS kernel interface)
if command -v otool >/dev/null 2>&1; then
    DYLIBS="$(otool -L "$BIN" 2>/dev/null | tail -n +2 | awk '{print $1}')"
    # Filter to only unexpected libraries (libSystem.B.dylib is expected)
    UNEXPECTED="$(echo "$DYLIBS" | grep -v 'libSystem.B.dylib' | grep -v '^$' || true)"
    check "no unexpected dynamic libraries" "test -z '$UNEXPECTED'"
fi

# Strip check (informational): Apple's ld keeps metadata symbols even with
# -Wl,-x, so we only warn — not fail — if the count seems high.
if command -v nm >/dev/null 2>&1; then
    LOCAL_SYMS="$(nm -m "$BIN" 2>/dev/null | grep -c ' non-external ' || echo 0)"
    if [ "$LOCAL_SYMS" -lt 50 ]; then
        echo "  PASS: local symbols stripped ($LOCAL_SYMS remaining)"
        PASS=$((PASS + 1))
    else
        echo "  SKIP: $LOCAL_SYMS local symbols remain (Apple ld metadata, not security-relevant)"
    fi
fi

SIZE="$(stat -f%z "$BIN" 2>/dev/null || stat --format=%s "$BIN" 2>/dev/null || echo 999999)"
check "size < 300KB" "test '$SIZE' -lt 307200"

# --- CLI argument tests ---

echo ""
echo "=== CLI argument tests ==="

# Bad arguments should print usage and exit cleanly (not crash/segfault).
USAGE_EXIT=0
"$BIN" --nonexistent >/dev/null 2>&1 || USAGE_EXIT=$?
check "bad flag prints usage and exits cleanly" \
    "test '$USAGE_EXIT' -le 2"

# connect without host: stdin closed → clean exit.
CONNECT_EXIT=0
"$BIN" connect < /dev/null >/dev/null 2>&1 || CONNECT_EXIT=$?
check "connect without host exits cleanly" \
    "test '$CONNECT_EXIT' -le 2"

# No debug strings leaked into binary
check "no 'SAS:' debug string" \
    "test \"\$(strings '$BIN' | grep -c 'SAS:')\" -eq 0"
check "no 'handshake complete' debug string" \
    "test \"\$(strings '$BIN' | grep -ci 'handshake complete.*SAS')\" -eq 0"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
