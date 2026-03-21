#!/usr/bin/env bash
# test_tui.sh — End-to-end TUI mode test using tmux.
#
# Drives two SimpleCipher instances in TUI mode through a full session:
#   1. Listener starts in TUI mode
#   2. Connector connects in TUI mode
#   3. Both reach SAS verification screen
#   4. Both type the SAS code to confirm
#   5. Both enter the chat screen
#   6. Each side sends a message
#   7. Verify messages appear on the other side
#
# Requires: tmux, a native SimpleCipher binary
#
# Usage: bash tests/test_tui.sh [path/to/simplecipher]
set -uo pipefail

BIN="${1:-./simplecipher}"
PORT=18765
SESSION_L="sc_tui_listen"
SESSION_C="sc_tui_connect"
PASS=0
FAIL=0

cleanup() {
    tmux kill-session -t "$SESSION_L" 2>/dev/null || true
    tmux kill-session -t "$SESSION_C" 2>/dev/null || true
}
trap cleanup EXIT

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

capture() {
    tmux capture-pane -t "$1" -p 2>/dev/null
}

# Sanity checks
if ! command -v tmux >/dev/null 2>&1; then
    echo "SKIP: tmux not installed"
    exit 0
fi
if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found or not executable: $BIN"
    exit 1
fi

echo "=== TUI mode integration test ==="

# Clean up any leftover sessions
cleanup

# --- Step 1: Start listener ---
tmux new-session -d -s "$SESSION_L" -x 80 -y 24 "$BIN --tui listen $PORT"
sleep 1

SCREEN_L="$(capture "$SESSION_L")"
check "listener shows title" "echo '$SCREEN_L' | grep -q 'SimpleCipher'"
check "listener shows waiting" "echo '$SCREEN_L' | grep -q 'Waiting on port'"

# --- Step 2: Start connector ---
tmux new-session -d -s "$SESSION_C" -x 80 -y 24 "$BIN --tui connect 127.0.0.1 $PORT"
sleep 2

# --- Step 3: Both should show SAS screen ---
SCREEN_L="$(capture "$SESSION_L")"
SCREEN_C="$(capture "$SESSION_C")"
check "listener shows SAS screen" "echo '$SCREEN_L' | grep -q 'Verify safety code'"
check "connector shows SAS screen" "echo '$SCREEN_C' | grep -q 'Verify safety code'"

# Extract SAS code from listener screen (format: XXXX-XXXX)
SAS="$(echo "$SCREEN_L" | grep -oE '[A-F0-9]{4}-[A-F0-9]{4}' | head -1)"
if [ -z "$SAS" ]; then
    echo "  FAIL: could not extract SAS code from listener screen"
    FAIL=$((FAIL + 1))
    echo ""
    echo "=== Results: $PASS passed, $FAIL failed ==="
    exit 1
fi
SAS_PREFIX="${SAS:0:4}"
check "SAS code extracted" "test -n '$SAS_PREFIX'"

# Verify same SAS on both sides
SAS_C="$(echo "$SCREEN_C" | grep -oE '[A-F0-9]{4}-[A-F0-9]{4}' | head -1)"
check "SAS codes match" "test '$SAS' = '$SAS_C'"

# --- Step 4: Type SAS code on both sides ---
for ch in $(echo "$SAS_PREFIX" | grep -o .); do
    tmux send-keys -t "$SESSION_L" "$ch"
    tmux send-keys -t "$SESSION_C" "$ch"
    sleep 0.1
done
sleep 1

# --- Step 5: Both should enter chat screen ---
SCREEN_L="$(capture "$SESSION_L")"
SCREEN_C="$(capture "$SESSION_C")"
check "listener shows chat screen" "echo '$SCREEN_L' | grep -q 'Secure session active'"
check "connector shows chat screen" "echo '$SCREEN_C' | grep -q 'Secure session active'"

# --- Step 6: Send messages ---
# Listener sends "hello from listener"
tmux send-keys -t "$SESSION_L" "hello from listener" Enter
sleep 1

# Connector sends "hello from connector"
tmux send-keys -t "$SESSION_C" "hello from connector" Enter
sleep 1

# --- Step 7: Verify messages ---
SCREEN_L="$(capture "$SESSION_L")"
SCREEN_C="$(capture "$SESSION_C")"

check "listener sees own message" "echo '$SCREEN_L' | grep -q 'hello from listener'"
check "connector sees listener message" "echo '$SCREEN_C' | grep -q 'hello from listener'"
check "connector sees own message" "echo '$SCREEN_C' | grep -q 'hello from connector'"
check "listener sees connector message" "echo '$SCREEN_L' | grep -q 'hello from connector'"

# Check message labels
check "listener labels own msg as 'me'" "echo '$SCREEN_L' | grep 'hello from listener' | grep -q 'me'"
check "listener labels peer msg as 'peer'" "echo '$SCREEN_L' | grep 'hello from connector' | grep -q 'peer'"

# --- Step 8: Clean exit ---
tmux send-keys -t "$SESSION_L" C-c
sleep 0.5
check "listener exited" "! tmux has-session -t '$SESSION_L' 2>/dev/null"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
