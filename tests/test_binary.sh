#!/usr/bin/env bash
# Local test runner — runs all test suites that can execute locally.
# Requires both targets already built.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
# Reject paths with shell metacharacters to prevent eval injection.
case "$PROJECT_DIR" in *[\'\"\`\$\;\&\|\!\(\)\{\}\[\]]*) echo "ERROR: project path contains shell metacharacters" >&2; exit 1;; esac
RC=0

run_suite() {
    local name="$1"
    shift
    echo "========================================="
    echo " $name"
    echo "========================================="
    if "$@"; then
        echo ""
    else
        RC=1
        echo ""
    fi
}

# P2P integration test (crypto + loopback + message exchange)
if [ -f "$PROJECT_DIR/build/native/test_p2p" ]; then
    run_suite "P2P integration tests" \
        "$PROJECT_DIR/build/native/test_p2p"
fi

# Build-level tests (CMake configure, C23 requirement)
run_suite "Build tests" \
    bash "$SCRIPT_DIR/test_build.sh"

# Linux binary: smoke + binary analysis
run_suite "Linux binary tests" \
    bash "$SCRIPT_DIR/test_linux.sh" \
    "$PROJECT_DIR/build/linux_x86_64/simplecipher"

# Windows binary: format and size checks (no native execution on Linux)
echo "========================================="
echo " Windows binary tests (format/size only)"
echo "========================================="

WIN_BIN="$PROJECT_DIR/build/win_x86_64/simplecipher.exe"
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

check "exists" "test -f '$WIN_BIN'"

FILE_INFO="$(file "$WIN_BIN" 2>/dev/null || true)"
check "is PE32+ executable" "echo '$FILE_INFO' | grep -q 'PE32+'"
check "architecture is x86-64" "echo '$FILE_INFO' | grep -q 'x86-64'"
SIZE="$(stat --format=%s "$WIN_BIN" 2>/dev/null || stat -f%z "$WIN_BIN" 2>/dev/null || echo 999999)"
check "size < 256KB" "test '$SIZE' -lt 262144"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || RC=1
echo ""

exit $RC
