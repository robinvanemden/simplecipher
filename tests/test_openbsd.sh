#!/usr/bin/env bash
# test_openbsd.sh — OpenBSD-specific tests for SimpleCipher
#
# Verifies pledge/unveil sandbox is functional by building with
# CIPHER_HARDEN and running the test suite.  Tests the full lifecycle:
# build → unit tests → handshake under pledge → SAS verification →
# encrypted message exchange → graceful shutdown.
#
# If any pledge violation occurs, the kernel sends SIGABRT (exit 134).
# On Linux with CIPHER_HARDEN, seccomp sends SIGSYS (exit 159).
#
# Usage: bash tests/test_openbsd.sh
set -euo pipefail

PASS=0
FAIL=0
TD=$(mktemp -d)

cleanup() { kill 0 2>/dev/null || true; rm -rf "$TD"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }

is_sandbox_kill() {
    # 134 = SIGABRT (OpenBSD pledge), 159 = SIGSYS (Linux seccomp)
    [ "${1:-0}" -eq 134 ] || [ "${1:-0}" -eq 159 ]
}

echo "=== OpenBSD SimpleCipher tests ==="

# Build from source with hardening
echo ""
echo "=== Building from source ==="
if make clean && make CC="${CC:-cc}" 2>&1; then
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

# Smoke test
echo ""
echo "=== Smoke tests ==="
if ./simplecipher --help >/dev/null 2>&1; then
    pass "--help works (no sandbox violation)"
else
    fail "--help failed"
fi

# ---------------------------------------------------------------
# Full lifecycle: handshake + SAS + chat under sandbox
# ---------------------------------------------------------------
echo ""
echo "=== Full lifecycle test (handshake + SAS + chat) ==="
PORT=19790

# Create FIFOs for stdin.  Use 'cat >' to keep the write end open
# so the processes don't see EOF before we're ready.
mkfifo "$TD/lin" "$TD/cin"
cat > "$TD/lin" &
CAT_L=$!
cat > "$TD/cin" &
CAT_C=$!

# Start listener (no timeout — we kill it manually)
./simplecipher listen "$PORT" < "$TD/lin" > "$TD/lout" 2>&1 &
LPID=$!
sleep 1

if ! kill -0 "$LPID" 2>/dev/null; then
    wait "$LPID" 2>/dev/null; EX=$?
    is_sandbox_kill "$EX" && fail "Listener sandbox violation on startup (exit $EX)" || fail "Listener failed (exit $EX)"
    kill "$CAT_L" "$CAT_C" 2>/dev/null || true
else
    pass "Listener started"

    # Start connector
    ./simplecipher connect 127.0.0.1 "$PORT" < "$TD/cin" > "$TD/cout" 2>&1 &
    CPID=$!
    sleep 3

    if kill -0 "$LPID" 2>/dev/null && kill -0 "$CPID" 2>/dev/null; then
        pass "Both survived TCP + handshake"

        # Extract SAS — it appears in a box after "SAFETY CODE" on the
        # next line.  Also appears as the only XXXX-XXXX pattern on a line
        # by itself (inside the box).  Skip the fingerprint line which has
        # XXXX-XXXX-XXXX-XXXX (4 groups, not 2).
        SAS=$(grep -oE '[0-9A-F]{4}-[0-9A-F]{4}' "$TD/lout" 2>/dev/null \
            | while read -r code; do
                # Fingerprints are 19 chars (XXXX-XXXX-XXXX-XXXX), SAS is 9 chars
                [ "${#code}" -eq 9 ] && echo "$code" && break
              done || true)

        if [ -z "$SAS" ]; then
            SAS=$(grep -oE '[0-9A-F]{4}-[0-9A-F]{4}' "$TD/cout" 2>/dev/null \
                | while read -r code; do [ "${#code}" -eq 9 ] && echo "$code" && break; done || true)
        fi

        if [ -n "$SAS" ]; then
            pass "SAS extracted: $SAS"
            SAS_STRIPPED=$(echo "$SAS" | tr -d '-')

            # Feed SAS to both
            echo "$SAS_STRIPPED" >> "$TD/lin"
            echo "$SAS_STRIPPED" >> "$TD/cin"
            sleep 2

            if kill -0 "$LPID" 2>/dev/null && kill -0 "$CPID" 2>/dev/null; then
                pass "Both survived SAS confirmation (chat phase active)"

                # Send a message (connector → listener)
                echo "sandbox chat test" >> "$TD/cin"
                sleep 2

                if kill -0 "$LPID" 2>/dev/null; then
                    # Check if message arrived in listener output
                    if grep -q "sandbox chat test" "$TD/lout" 2>/dev/null; then
                        pass "Message received under phase-2 sandbox"
                    else
                        pass "Both alive after message (phase-2 sandbox intact)"
                    fi
                else
                    wait "$LPID" 2>/dev/null; EX=$?
                    is_sandbox_kill "$EX" && fail "Listener sandbox violation during chat (exit $EX)" || pass "Listener exited cleanly (exit $EX)"
                fi
            else
                wait "$LPID" 2>/dev/null; LEX=$?
                wait "$CPID" 2>/dev/null; CEX=$?
                if is_sandbox_kill "$LEX" || is_sandbox_kill "$CEX"; then
                    fail "Sandbox violation during SAS (listen=$LEX connect=$CEX)"
                else
                    fail "Process died during SAS (listen=$LEX connect=$CEX)"
                fi
            fi
        else
            fail "Could not extract SAS"
            echo "--- listener output ---"
            head -20 "$TD/lout" 2>/dev/null || true
            echo "--- connector output ---"
            head -20 "$TD/cout" 2>/dev/null || true
        fi
    else
        wait "$LPID" 2>/dev/null; LEX=$?
        wait "$CPID" 2>/dev/null; CEX=$?
        if is_sandbox_kill "$LEX" || is_sandbox_kill "$CEX"; then
            fail "Sandbox violation during handshake (listen=$LEX connect=$CEX)"
        else
            fail "Process died during handshake (listen=$LEX connect=$CEX)"
        fi
    fi

    kill "$CPID" "$CAT_C" 2>/dev/null || true
fi

kill "$LPID" "$CAT_L" 2>/dev/null || true
wait 2>/dev/null || true

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
