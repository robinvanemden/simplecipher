#!/usr/bin/env bash
# test_helpers.sh — Shared helpers for SimpleCipher test scripts.
# Source this file: . "$(dirname "$0")/test_helpers.sh"

# Wait for a TCP port to accept connections (up to $2 seconds, default 5).
# Uses /dev/tcp which is a bash builtin — no external tools needed.
wait_for_port() {
    local port="$1" timeout="${2:-5}" i
    for ((i = 0; i < timeout * 10; i++)); do
        if (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    return 1
}

# Pick a random available port by probing [20000, 60000).
random_port() {
    local i p
    for ((i = 0; i < 50; i++)); do
        p=$((20000 + RANDOM % 40000))
        if ! (echo >/dev/tcp/127.0.0.1/"$p") 2>/dev/null; then echo "$p"; return 0; fi
    done
    echo "$((20000 + RANDOM % 40000))"
}
