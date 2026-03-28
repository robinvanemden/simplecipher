#!/bin/bash
#
# simplecipher-gui.sh — GUI launcher for SimpleCipher (Linux)
#
# Opens a simple dialog to choose Listen/Connect, enter host/port,
# then launches the simplecipher binary in a terminal.
#
# Requires: zenity (installed on most GNOME/GTK desktops)
#           A terminal emulator (tries: x-terminal-emulator, gnome-terminal,
#           konsole, xfce4-terminal, xterm)
#
# Usage: ./simplecipher-gui.sh
#        Double-click from a file manager also works.

set -e

# Find the simplecipher binary (same directory as this script, or in PATH)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -x "$SCRIPT_DIR/simplecipher" ]; then
    CIPHER="$SCRIPT_DIR/simplecipher"
elif command -v simplecipher >/dev/null 2>&1; then
    CIPHER="simplecipher"
else
    zenity --error --title="SimpleCipher" \
           --text="Cannot find simplecipher binary.\nPlace it next to this script or add it to PATH." \
           --width=350 2>/dev/null
    exit 1
fi

# Check for zenity
if ! command -v zenity >/dev/null 2>&1; then
    echo "zenity is required for the GUI launcher."
    echo "Install it with: sudo apt install zenity"
    exit 1
fi

# Find a terminal emulator
find_terminal() {
    for term in x-terminal-emulator gnome-terminal konsole xfce4-terminal alacritty kitty xterm; do
        if command -v "$term" >/dev/null 2>&1; then
            echo "$term"
            return
        fi
    done
}

TERM_EMU="$(find_terminal)"
if [ -z "$TERM_EMU" ]; then
    zenity --error --title="SimpleCipher" \
           --text="No terminal emulator found.\nInstall gnome-terminal, konsole, or xterm." \
           --width=350 2>/dev/null
    exit 1
fi

# Mode selection
MODE=$(zenity --list --title="SimpleCipher" \
       --text="Choose a mode:" \
       --column="Mode" --column="Description" \
       "Listen" "Wait for someone to connect to you" \
       "Connect" "Connect to someone who is listening" \
       --width=400 --height=250 2>/dev/null) || exit 0

# Port input
PORT=$(zenity --entry --title="SimpleCipher" \
       --text="Port number (default: 7777):" \
       --entry-text="7777" \
       --width=300 2>/dev/null) || exit 0
PORT="${PORT:-7777}"

# Host input (Connect mode only)
HOST=""
if [ "$MODE" = "Connect" ]; then
    HOST=$(zenity --entry --title="SimpleCipher" \
           --text="Host or IP address to connect to:" \
           --width=350 2>/dev/null) || exit 0
    if [ -z "$HOST" ]; then
        zenity --error --title="SimpleCipher" \
               --text="Host is required for Connect mode." \
               --width=300 2>/dev/null
        exit 1
    fi
fi

# TUI mode toggle
USE_TUI=""
if zenity --question --title="SimpleCipher" \
          --text="Use the split-pane terminal interface (TUI)?\n\nTUI gives you a nicer chat layout.\nCLI is simpler but functional." \
          --ok-label="Yes, use TUI" --cancel-label="No, plain CLI" \
          --width=350 2>/dev/null; then
    USE_TUI="--tui"
fi

# Validate inputs — reject shell metacharacters to prevent command injection
validate_input() {
    local name="$1" value="$2" pattern="$3"
    if ! printf '%s' "$value" | grep -qE "^${pattern}\$"; then
        zenity --error --title="SimpleCipher" \
               --text="Invalid ${name}: '${value}'\nOnly alphanumeric characters, dots, colons, underscores, and hyphens are allowed." \
               --width=400 2>/dev/null
        exit 1
    fi
}

validate_input "port" "$PORT" '[0-9]+'
if [ -n "$HOST" ]; then
    validate_input "host" "$HOST" '[a-zA-Z0-9._:-]+'
fi

# Build the command as an array (prevents injection via string splitting)
CMD_ARGS=("$CIPHER")
if [ -n "$USE_TUI" ]; then
    CMD_ARGS+=("$USE_TUI")
fi
if [ "$MODE" = "Listen" ]; then
    CMD_ARGS+=("listen" "$PORT")
else
    CMD_ARGS+=("connect" "$HOST" "$PORT")
fi

# Write a safe launcher script that uses exec with proper quoting
# This avoids passing user input through bash -c string interpretation
LAUNCH_SCRIPT=$(mktemp /tmp/simplecipher-launch.XXXXXX.sh)
chmod 700 "$LAUNCH_SCRIPT"
{
    printf '#!/bin/bash\n'
    # Write each argument individually quoted via printf %q
    printf 'exec'
    for arg in "${CMD_ARGS[@]}"; do
        printf ' %q' "$arg"
    done
    printf '\n'
} > "$LAUNCH_SCRIPT"

# Wrapper that runs the launcher then prompts before closing
WRAPPER_SCRIPT=$(mktemp /tmp/simplecipher-wrapper.XXXXXX.sh)
chmod 700 "$WRAPPER_SCRIPT"
cat > "$WRAPPER_SCRIPT" <<WRAPPER
#!/bin/bash
bash "$LAUNCH_SCRIPT"
echo
echo 'Press Enter to close...'
read
rm -f "$LAUNCH_SCRIPT" "$WRAPPER_SCRIPT"
WRAPPER

# Launch in a terminal
# Different terminals have different exec flag syntax
case "$TERM_EMU" in
    gnome-terminal)
        $TERM_EMU -- bash "$WRAPPER_SCRIPT" ;;
    konsole)
        $TERM_EMU -e bash "$WRAPPER_SCRIPT" ;;
    xfce4-terminal)
        $TERM_EMU -e "bash '$WRAPPER_SCRIPT'" ;;
    *)
        $TERM_EMU -e bash "$WRAPPER_SCRIPT" ;;
esac
