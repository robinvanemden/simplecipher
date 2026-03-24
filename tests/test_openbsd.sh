#!/usr/bin/env bash
# test_openbsd.sh — OpenBSD-specific tests for SimpleCipher
#
# Verifies pledge/unveil sandbox is functional by building with
# CIPHER_HARDEN and running the test suite.  Also checks that the
# binary runs without pledge violations (ktrace would show SIGABRT).
#
# Usage: bash tests/test_openbsd.sh
set -euo pipefail

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }

echo "=== OpenBSD SimpleCipher tests ==="

# Build from source with hardening (pledge/unveil activated)
echo ""
echo "=== Building from source ==="
if make clean && make CC=cc 2>&1; then
    pass "Build succeeded"
else
    fail "Build failed"
    exit 1
fi

# Run unit tests
echo ""
echo "=== Running unit tests ==="
if make test 2>&1; then
    pass "Unit tests passed"
else
    fail "Unit tests failed"
fi

# Smoke test: run the binary with --help (should not trigger pledge violation)
echo ""
echo "=== Smoke tests ==="
if ./simplecipher --help >/dev/null 2>&1; then
    pass "--help works (no pledge violation)"
else
    fail "--help failed (possible pledge violation)"
fi

# Listen + connect loopback: verify pledge doesn't kill the handshake.
# Phase 1 pledge("stdio") is installed AFTER the TCP connection, so
# listen/connect should work.  The handshake uses only read/write/getrandom
# which are covered by "stdio".
echo ""
echo "=== Loopback handshake test ==="
PORT=19780

# Start listener in background
./simplecipher listen "$PORT" &
LISTEN_PID=$!
sleep 1

# Connect (will fail SAS — that's fine, we just want no pledge crash)
timeout 5 ./simplecipher connect 127.0.0.1 "$PORT" </dev/null >/dev/null 2>&1 &
CONNECT_PID=$!
sleep 3

# Check if listener is still alive (pledge violation = SIGABRT = dead)
if kill -0 "$LISTEN_PID" 2>/dev/null; then
    pass "Listener survived handshake (no pledge violation)"
else
    # Check exit code
    wait "$LISTEN_PID" 2>/dev/null
    EXIT_CODE=$?
    if [ "$EXIT_CODE" -eq 134 ]; then
        fail "Listener killed by SIGABRT (pledge violation!)"
    else
        pass "Listener exited cleanly (exit code $EXIT_CODE)"
    fi
fi

# Cleanup
kill "$LISTEN_PID" 2>/dev/null || true
kill "$CONNECT_PID" 2>/dev/null || true
wait "$LISTEN_PID" 2>/dev/null || true
wait "$CONNECT_PID" 2>/dev/null || true

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
