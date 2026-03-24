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

# Extract the first local IP shown by the listener
LOCAL_IP=$(grep -oP 'connect \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /tmp/sc_demo_listen.txt 2>/dev/null | head -1 || true)

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
echo "Captured local IP: ${LOCAL_IP:-192.168.1.42}"

IP="${LOCAL_IP:-192.168.1.42}"

# Build the phone call box with proper alignment.
# The 📞 emoji is 4 bytes but 2 display columns, so printf %-Ns
# undercounts by 2.  We add 2 extra bytes to the emoji line width.
W=50  # inner width (display columns)
BOX_TOP="         ╔$(printf '═%.0s' $(seq 1 $W))╗"
BOX_BOT="         ╚$(printf '═%.0s' $(seq 1 $W))╝"
box_line() { printf '         ║  %-*s║' "$((W-2))" "$1"; }
# +2 bytes for emoji display-width compensation
box_line_emoji() { printf '         ║  %-*s║' "$((W))" "$1"; }
PHONE1=$(box_line_emoji "📞  Phone call:")
PHONE2=$(box_line "Alice: \"I see $SAS -- same for you?\"")
PHONE3=$(box_line "Bob:   \"Yes, same code.\"")

# Generate the demo block
DEMO=$(cat << DEMOEOF
\`\`\`
 ALICE (listener)                          BOB (connector)
 ─────────────────                         ────────────────
 \$ simplecipher listen

   Listening on port 7777
   Tell your peer to run:
     simplecipher connect $IP
   Your fingerprint: ${FINGERPRINT:-B4C7-2E19-A5D3-F801}
   Waiting for connection...
                                            \$ simplecipher connect $IP
   Safety code:  $SAS                    Safety code:  $SAS

$BOX_TOP
$PHONE1
$PHONE2
$PHONE3
$BOX_BOT

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
# Write the demo to a temp file, then use Python to patch README
echo "$DEMO" > /tmp/sc_demo_block.txt

python3 - "$README" /tmp/sc_demo_block.txt "$SAS" << 'PYEOF'
import re, sys

readme_path = sys.argv[1]
demo_path = sys.argv[2]
sas = sys.argv[3]

with open(readme_path) as f:
    content = f.read()

with open(demo_path) as f:
    demo = f.read().strip()

# Match: ``` ... ``` block that starts with " ALICE (listener)"
pattern = r'(?s)```\n ALICE \(listener\).*?```'
if re.search(pattern, content):
    content = re.sub(pattern, demo, content)
    with open(readme_path, "w") as f:
        f.write(content)
    print(f"README.md updated with real SAS code: {sas}")
else:
    print("ERROR: Could not find demo block in README.md")
    sys.exit(1)
PYEOF
rm -f /tmp/sc_demo_block.txt
