/*
 * tui.h — Text User Interface for SimpleCipher
 *
 * Everything in this module is OPTIONAL PRESENTATION CODE.  It draws a
 * box-art chat window in the terminal using ANSI escape sequences.  None
 * of this affects the protocol, cryptography, or security properties
 * described in crypto.h and protocol.h -- it is purely cosmetic.
 *
 * If you are reading this codebase to learn P2P crypto, you can skip this
 * module entirely.  The protocol is complete without it: key exchange,
 * commitment scheme, session derivation, forward-secrecy ratchet, frame
 * encryption, and the CLI event loops are all in other modules.
 *
 * HOW TERMINAL RAW MODE WORKS
 * ===========================
 * Terminals normally operate in "cooked" (canonical) mode: the OS buffers
 * typed characters until Enter is pressed, handles backspace internally,
 * and echoes characters back to the screen.  This is great for line-by-line
 * input but terrible for a TUI that needs to:
 *   - react to every keypress immediately (no waiting for Enter)
 *   - suppress automatic echo (we draw our own input line)
 *   - handle Ctrl+C ourselves (clean shutdown, not abrupt SIGINT)
 *
 * To get this control, we switch the terminal to "raw" mode by clearing
 * flags in the termios structure (POSIX) or adjusting console modes
 * (Windows).  We save the original settings and restore them on exit
 * via atexit() so the terminal is not left in a broken state.
 *
 * ANSI ESCAPE SEQUENCES
 * =====================
 * We draw the UI by printing ANSI/VT100 escape sequences:
 *   \033[y;xH   -- move cursor to row y, column x
 *   \033[2K     -- erase the entire current line
 *   \033[2J     -- clear the entire screen
 *   \033[?25h/l -- show/hide the cursor
 *   \033[0m     -- reset all text attributes
 *   \033[2m     -- dim text
 *   \033[36m    -- cyan foreground
 * These are supported by virtually all modern terminals and by the Windows
 * Console (with ENABLE_VIRTUAL_TERMINAL_PROCESSING enabled).
 *
 * BOX-DRAWING CHARACTERS
 * ======================
 * The border uses Unicode box-drawing characters (U+250x..U+251x),
 * encoded as UTF-8.  For example:
 *   \xe2\x94\x8c = ┌   \xe2\x94\x90 = ┐
 *   \xe2\x94\x9c = ├   \xe2\x94\xa4 = ┤
 *   \xe2\x94\x94 = └   \xe2\x94\x98 = ┘
 *   \xe2\x94\x80 = ─   \xe2\x94\x82 = │
 *
 * SCREEN LAYOUT
 * =============
 *   Row 1:       ┌── SimpleCipher ─────────────────┐   (title bar)
 *   Row 2:       │ Secure session active | Ctrl+C  │   (status bar)
 *   Row 3:       ├────────────────────────────────────┤ (separator)
 *   Rows 4..H-2: │ [HH:MM:SS] peer: hello          │   (message area)
 *   Row H-1:     ├────────────────────────────────────┤ (separator)
 *   Row H:       └ > typed text here                ┘   (input line)
 *
 * Read next: tui.c (shared drawing code), tui_posix.c / tui_win.c (event loops)
 */

#ifndef SIMPLECIPHER_TUI_H
#define SIMPLECIPHER_TUI_H

#include "protocol.h"
#include "network.h"

/* ---- TUI layout constants ----------------------------------------------- */

enum {
    TUI_DEFAULT_WIDTH     = 80, /* classic VT100 fallback width             */
    TUI_DEFAULT_HEIGHT    = 24, /* classic VT100 fallback height            */
    TUI_MIN_WIDTH         = 40, /* minimum usable terminal width            */
    TUI_MIN_HEIGHT        = 14, /* minimum height for full chat UI          */
    TUI_MIN_STATUS_HEIGHT = 10, /* minimum height for status/listen screens */
    TUI_MSG_AREA_TOP      = 4,  /* row where the message area starts        */
    TUI_TITLE_OFFSET      = 16, /* column offset for title border drawing   */
    TUI_MIN_SAS_LEN       = 4,  /* minimum typed chars before Enter accepted */
};

/* ---- TUI: message ring buffer -------------------------------------------
 *
 * Chat messages are stored in a fixed-size circular buffer (ring buffer).
 * A ring buffer has constant memory usage regardless of how long the chat
 * runs: once the buffer is full, the oldest message is overwritten by the
 * newest one.  This is the same structure used in OS kernel log buffers
 * (dmesg) and network packet capture rings.
 *
 * tui_msg_start is the index of the oldest message in the ring.
 * tui_msg_count is the total number of messages ever inserted (capped at
 * TUI_MSG_MAX).  When count < max, messages are appended linearly.
 * When count == max, the oldest slot is reused and start advances.
 *
 * The display code reads the most recent N messages (where N = visible
 * rows) by indexing from (start + total - N) % TUI_MSG_MAX. */
#define TUI_MSG_MAX 1000
#define TUI_MSG_TEXT (MAX_MSG + 1) /* must hold null-terminated message */

enum tui_sender { TUI_ME, TUI_PEER, TUI_SYSTEM };

/* The ring buffer is declared as extern so both tui.c and the platform
 * event loop files (tui_posix.c / tui_win.c) can access it. */
extern struct tui_msg_entry {
    char            ts[TIMESTAMP_BUF]; /* "HH:MM:SS" timestamp of the message */
    enum tui_sender who;               /* who sent it: local user, peer, or system */
    char            text[TUI_MSG_TEXT];
} tui_msgs[TUI_MSG_MAX];

extern int tui_msg_count; /* total messages stored (up to TUI_MSG_MAX) */
extern int tui_msg_start; /* index of oldest message in the ring */

/* Cursor-movement and colour escape sequences as macros for readability. */
#define TUI_GOTO(r, c) printf("\033[%d;%dH", (r), (c))
#define TUI_CLEAR_LINE() printf("\033[2K")
#define TUI_COLOR_RESET "\033[0m"
#define TUI_COLOR_DIM "\033[2m"
#define TUI_COLOR_CYAN "\033[36m"
#define TUI_COLOR_BCYAN "\033[1;36m"
#define TUI_COLOR_YELLOW "\033[33m"
#define TUI_COLOR_GREEN "\033[32m"

/* Cached terminal dimensions, updated by tui_get_size(). */
extern int tui_w, tui_h;

/* ---- ring buffer operations --------------------------------------------- */

/* Wipe all plaintext messages from the ring buffer.
 * Called at session shutdown so chat history does not linger in RAM. */
void tui_msg_wipe(void);

/* Append a message to the ring buffer, overwriting the oldest if full. */
void tui_msg_add(enum tui_sender who, const char *text);

/* ---- drawing functions -------------------------------------------------- */

/* Query the current terminal dimensions in columns (w) and rows (h). */
void tui_get_size(int *w, int *h);

/* Draw a horizontal border line at the given row.
 * left_ch / right_ch: 1=top corner, 2=tee, 3=bottom corner. */
void tui_draw_hline(int row, int left_ch, int right_ch);

/* Draw the title bar (row 1). */
void tui_draw_title(void);

/* Draw the status bar (row 2). */
void tui_draw_status(const char *status);

/* Render the message area (rows 4 through H-2). */
void tui_draw_messages(void);

/* Draw the input line (bottom row). */
void tui_draw_input(const char *line, size_t len);

/* Full-screen redraw: title, status, separators, messages, input. */
void tui_draw_screen(const char *status, const char *line, size_t line_len);

/* Show a centred status message (e.g. "Connecting to host:port ..."). */
void tui_status_screen(const char *line1, const char *line2);

/* Show the listen screen with port and local IP addresses.
 * ips is a newline-separated string of IP addresses (from get_local_ips). */
void tui_listen_screen(const char *port, const char *ips);

/* Display the SAS verification screen and require user to type the full
 * code to confirm.  Returns 1 on match, 0 on user abort (Ctrl+C,
 * terminal too small, or peer disconnect), -1 on code mismatch.
 * sas_fd is the peer socket — monitored for disconnect during input. */
int tui_sas_screen(const char *sas, socket_t sas_fd);

/* ---- platform-specific functions ----------------------------------------
 *
 * These have the SAME function names in tui_posix.c and tui_win.c.
 * Only one file is compiled per platform. */

/* Switch terminal to raw mode / restore original terminal settings. */
void tui_init_term(void);
void tui_restore_term(void);

/* TUI chat event loop.  Blocks until the session ends.
 * fd: the connected socket.  sess: the active crypto session.
 * cover: if non-zero, send encrypted dummy frames at random intervals
 *        to defeat Tor timing correlation attacks. */
void tui_chat_loop(socket_t fd, session_t *sess, int cover);

#endif /* SIMPLECIPHER_TUI_H */
