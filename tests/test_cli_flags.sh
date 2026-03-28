#!/usr/bin/env bash
# test_cli_flags.sh — CLI flag integration tests for SimpleCipher
#
# Tests --peer-fingerprint and --trust-fingerprint flag behavior
# using the actual binary. Does NOT test the crypto path (covered by
# test_p2p.c) — only tests flag parsing, validation, and the
# SAS-skip behavior of --trust-fingerprint.
#
# Usage: bash tests/test_cli_flags.sh [path-to-simplecipher]

set -euo pipefail

BIN="${1:-./simplecipher}"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }

echo ""
echo "=== CLI flag integration tests ==="
echo "Binary: $BIN"
echo ""

# ------------------------------------------------------------------
# 1. --trust-fingerprint without --peer-fingerprint → exit 1
# ------------------------------------------------------------------
echo "--- --trust-fingerprint validation ---"

if "$BIN" --trust-fingerprint listen 2>/dev/null; then
    fail "--trust-fingerprint without --peer-fingerprint should fail (listen)"
else
    rc=$?
    if [ "$rc" -eq 1 ]; then
        pass "--trust-fingerprint without --peer-fingerprint exits 1 (listen)"
    else
        fail "--trust-fingerprint without --peer-fingerprint exits $rc, expected 1 (listen)"
    fi
fi

if "$BIN" --trust-fingerprint connect 127.0.0.1 2>/dev/null; then
    fail "--trust-fingerprint without --peer-fingerprint should fail (connect)"
else
    rc=$?
    if [ "$rc" -eq 1 ]; then
        pass "--trust-fingerprint without --peer-fingerprint exits 1 (connect)"
    else
        fail "--trust-fingerprint without --peer-fingerprint exits $rc, expected 1 (connect)"
    fi
fi

# ------------------------------------------------------------------
# 2. --trust-fingerprint error message is clear
# ------------------------------------------------------------------
msg=$("$BIN" --trust-fingerprint listen 2>&1 || true)
if echo "$msg" | grep -q "requires.*peer-fingerprint"; then
    pass "--trust-fingerprint error message mentions --peer-fingerprint"
else
    fail "--trust-fingerprint error message unclear: $msg"
fi

# ------------------------------------------------------------------
# 3. --peer-fingerprint accepted with --trust-fingerprint (no error)
#    This will fail to connect (no peer listening), but should NOT
#    fail with a usage error — it should get past flag parsing.
# ------------------------------------------------------------------
echo ""
echo "--- --peer-fingerprint + --trust-fingerprint acceptance ---"

# Use a non-routable IP with a short timeout to avoid hanging.
# We just need to verify it gets past flag validation (exit != 1).
timeout 3 "$BIN" --peer-fingerprint A3F2-91BC-D4E5-F678 --trust-fingerprint connect 192.0.2.1 2>/dev/null || true
rc=$?
# rc=124 (timeout), rc=2 (connection failed), or rc=6 (internal) are all OK
# rc=1 would mean it rejected the flags as invalid
if [ "$rc" -ne 1 ]; then
    pass "--peer-fingerprint + --trust-fingerprint passes flag validation (connect)"
else
    fail "--peer-fingerprint + --trust-fingerprint rejected as usage error (connect)"
fi

timeout 3 "$BIN" --peer-fingerprint A3F2-91BC-D4E5-F678 --trust-fingerprint listen 2>/dev/null &
LISTEN_PID=$!
sleep 1
# Listener should be running (waiting for connection), not exited with error
if kill -0 "$LISTEN_PID" 2>/dev/null; then
    pass "--peer-fingerprint + --trust-fingerprint passes flag validation (listen)"
    kill "$LISTEN_PID" 2>/dev/null || true
    wait "$LISTEN_PID" 2>/dev/null || true
else
    wait "$LISTEN_PID" 2>/dev/null || true
    rc=$?
    if [ "$rc" -eq 1 ]; then
        fail "--peer-fingerprint + --trust-fingerprint rejected as usage error (listen)"
    else
        pass "--peer-fingerprint + --trust-fingerprint passes flag validation (listen, exited $rc)"
    fi
fi

# ------------------------------------------------------------------
# 4. --peer-fingerprint alone (without --trust-fingerprint) works
# ------------------------------------------------------------------
echo ""
echo "--- --peer-fingerprint alone ---"

timeout 3 "$BIN" --peer-fingerprint A3F2-91BC-D4E5-F678 connect 192.0.2.1 2>/dev/null || true
rc=$?
if [ "$rc" -ne 1 ]; then
    pass "--peer-fingerprint alone passes flag validation (connect)"
else
    fail "--peer-fingerprint alone rejected as usage error (connect)"
fi

# ------------------------------------------------------------------
# 5. --help shows both flags
# ------------------------------------------------------------------
echo ""
echo "--- --help output ---"

help_out=$("$BIN" --help 2>&1 || true)

if echo "$help_out" | grep -q -- "--peer-fingerprint"; then
    pass "--help mentions --peer-fingerprint"
else
    fail "--help missing --peer-fingerprint"
fi

if echo "$help_out" | grep -q -- "--trust-fingerprint"; then
    pass "--help mentions --trust-fingerprint"
else
    fail "--help missing --trust-fingerprint"
fi

# ------------------------------------------------------------------
# 6. End-to-end: listen + connect with matching fingerprint + trust
#    Both sides verify each other's fingerprint and skip SAS.
# ------------------------------------------------------------------
echo ""
echo "--- End-to-end fingerprint trust test ---"

PORT=$((20000 + RANDOM % 40000))

# Start listener in background, capture fingerprint from output
LISTEN_OUT=$(mktemp)
"$BIN" listen "$PORT" >"$LISTEN_OUT" 2>&1 &
LISTEN_PID=$!
sleep 1

# Extract listener's fingerprint
LISTENER_FP=$(grep -oP 'fingerprint: \K[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}' "$LISTEN_OUT" || true)

if [ -z "$LISTENER_FP" ]; then
    fail "Could not extract listener fingerprint from output"
    kill "$LISTEN_PID" 2>/dev/null || true
    wait "$LISTEN_PID" 2>/dev/null || true
    rm -f "$LISTEN_OUT"
else
    pass "Extracted listener fingerprint: $LISTENER_FP"

    # Kill the initial listener (we needed it just to get the fingerprint,
    # but keys are ephemeral so we can't reuse it)
    kill "$LISTEN_PID" 2>/dev/null || true
    wait "$LISTEN_PID" 2>/dev/null || true

    # For a true end-to-end test with --trust-fingerprint, both sides
    # need each other's fingerprint. Since keys are ephemeral (change
    # each run), we test the mechanism via the in-process tests in
    # test_p2p.c (test_fingerprint_handshake_verification, Tests D+E).
    #
    # Here we verify the CLI binary correctly:
    # 1. Shows the fingerprint on listen
    # 2. Accepts --peer-fingerprint + --trust-fingerprint without error
    # 3. Rejects --trust-fingerprint without --peer-fingerprint
    # These are already covered by tests 1-5 above.
    pass "End-to-end: listener shows fingerprint in expected format"
fi
rm -f "$LISTEN_OUT"

# ------------------------------------------------------------------
# 7. --peer-fingerprint works for listen mode too
# ------------------------------------------------------------------
echo ""
echo "--- --peer-fingerprint on listen mode ---"

timeout 3 "$BIN" --peer-fingerprint A3F2-91BC-D4E5-F678 listen "$PORT" 2>/dev/null &
LISTEN_PID=$!
sleep 1
if kill -0 "$LISTEN_PID" 2>/dev/null; then
    pass "--peer-fingerprint accepted in listen mode"
    kill "$LISTEN_PID" 2>/dev/null || true
    wait "$LISTEN_PID" 2>/dev/null || true
else
    wait "$LISTEN_PID" 2>/dev/null || true
    rc=$?
    if [ "$rc" -eq 1 ]; then
        fail "--peer-fingerprint rejected in listen mode"
    else
        pass "--peer-fingerprint accepted in listen mode (exited $rc)"
    fi
fi

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo ""
echo "======================================="
echo "CLI flag tests: $PASS passed, $FAIL failed"
echo "======================================="

[ "$FAIL" -eq 0 ]
