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

# Build the command
if [ "$MODE" = "Listen" ]; then
    CMD="$CIPHER $USE_TUI listen $PORT"
else
    CMD="$CIPHER $USE_TUI connect $HOST $PORT"
fi

# Launch in a terminal
# Different terminals have different exec flag syntax
case "$TERM_EMU" in
    gnome-terminal)
        $TERM_EMU -- bash -c "$CMD; echo; echo 'Press Enter to close...'; read" ;;
    konsole)
        $TERM_EMU -e bash -c "$CMD; echo; echo 'Press Enter to close...'; read" ;;
    xfce4-terminal)
        $TERM_EMU -e "bash -c \"$CMD; echo; echo 'Press Enter to close...'; read\"" ;;
    *)
        $TERM_EMU -e bash -c "$CMD; echo; echo 'Press Enter to close...'; read" ;;
esac
