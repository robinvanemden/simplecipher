#!/usr/bin/env bash
# Generate the ASCII session demo for README.md from a real session.
#
# Runs a listen + connect session on loopback, captures the actual SAS
# code, and updates the demo block in README.md with real values.
#
# Usage: bash docs/generate-demo.sh
# Requires: simplecipher binary built (make simplecipher)

set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PORT=19876
README="$PROJECT_DIR/README.md"

# Find the binary — check PATH first, then project root
BIN=$(command -v simplecipher 2>/dev/null || true)
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    BIN="$PROJECT_DIR/simplecipher"
fi
if [ ! -x "$BIN" ]; then
    echo "Build first: make simplecipher (or add to PATH)" >&2
    exit 1
fi
echo "Using binary: $BIN"

cleanup() {
    kill "$LISTEN_PID" "$CONNECT_PID" 2>/dev/null || true
    wait "$LISTEN_PID" "$CONNECT_PID" 2>/dev/null || true
    rm -f /tmp/sc_demo_listen.txt /tmp/sc_demo_connect.txt
}
trap cleanup EXIT

# Run a real session on loopback.
# Both sides will print the SAS code and wait for input.
# We capture the output, extract the SAS, then kill both.

$BIN listen "$PORT" > /tmp/sc_demo_listen.txt 2>&1 &
LISTEN_PID=$!
sleep 1

# Feed empty stdin so connect doesn't block on interactive prompt
echo "" | $BIN connect 127.0.0.1 "$PORT" > /tmp/sc_demo_connect.txt 2>&1 &
CONNECT_PID=$!
sleep 4

# Extract the SAS code from the listener output
SAS=$(grep -oP '[0-9A-F]{4}-[0-9A-F]{4}' /tmp/sc_demo_listen.txt 2>/dev/null | head -1 || true)

# Also try connector output
if [ -z "$SAS" ]; then
    SAS=$(grep -oP '[0-9A-F]{4}-[0-9A-F]{4}' /tmp/sc_demo_connect.txt 2>/dev/null | head -1 || true)
fi

# Extract the fingerprint from the listener output
FINGERPRINT=$(grep -oP '[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}' /tmp/sc_demo_listen.txt 2>/dev/null | head -1 || true)

# Kill both sessions
kill "$LISTEN_PID" "$CONNECT_PID" 2>/dev/null || true
wait "$LISTEN_PID" "$CONNECT_PID" 2>/dev/null || true

if [ -z "$SAS" ]; then
    echo "WARNING: Could not capture SAS code, using placeholder" >&2
    SAS="A3F2-91BC"
fi

SAS_NODASH=$(echo "$SAS" | tr -d '-')

echo "Captured SAS: $SAS"
echo "Captured fingerprint: ${FINGERPRINT:-none}"

# Generate the demo block
DEMO=$(cat << DEMOEOF
\`\`\`
 ALICE (listener)                          BOB (connector)
 ─────────────────                         ────────────────
 \$ simplecipher listen
   Your fingerprint: ${FINGERPRINT:-B4C7-2E19-A5D3-F801}
                                            \$ simplecipher connect 192.168.1.42
   Safety code:  $SAS                    Safety code:  $SAS

   Alice calls Bob: "I see $SAS"       Bob: "Same here"

   Confirm: $SAS_NODASH                          Confirm: $SAS_NODASH

   Secure session active.                     Secure session active.

 > hey, is this channel safe?
                                            [12:01:03] peer: hey, is this channel safe?
                                            > yes — keys are ephemeral, wiped on exit
 [12:01:07] peer: yes — keys are
   ephemeral, wiped on exit

   ^C                                         [peer disconnected]
   Keys wiped. Session over.                  Keys wiped. Session over.
\`\`\`
DEMOEOF
)

# Replace the demo block in README.md
# The block is between the lines matching "^```$" after "built for privacy"
# and before "**Deep dives:**"
python3 << PYEOF
import re

with open("$README") as f:
    content = f.read()

# Find and replace the demo block (between the first \`\`\` block after the intro
# and before **Deep dives:**)
demo = """$DEMO"""

# Match: ``` ... ``` block that comes before **Deep dives:**
pattern = r'(?s)\`\`\`\n ALICE \(listener\).*?\`\`\`'
if re.search(pattern, content):
    content = re.sub(pattern, demo.strip(), content)
    with open("$README", "w") as f:
        f.write(content)
    print("README.md updated with real SAS code: $SAS")
else:
    print("ERROR: Could not find demo block in README.md")
    exit(1)
PYEOF
