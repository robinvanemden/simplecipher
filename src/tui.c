/*
 * tui.c — Shared TUI drawing code for SimpleCipher
 *
 * Implements the ring buffer, drawing primitives, and screens that are
 * shared between POSIX and Windows.  The platform-specific terminal
 * setup and event loops live in tui_posix.c and tui_win.c respectively.
 */

#include "tui.h"

#ifndef _WIN32
#include <sys/ioctl.h>
#endif

/* ---- ring buffer state (extern declarations in tui.h) ------------------- */

struct tui_msg_entry tui_msgs[TUI_MSG_MAX];

int tui_msg_count = 0;    /* total messages stored (up to TUI_MSG_MAX) */
int tui_msg_start = 0;    /* index of oldest message in the ring */

int tui_w = 80, tui_h = 24;   /* cached terminal dimensions */

/* ---- ring buffer operations --------------------------------------------- */

/* Wipe all plaintext messages from the ring buffer.
 * Called at session shutdown so chat history does not linger in RAM.
 * Without this, a core dump or memory forensics tool could recover the
 * entire conversation even though all crypto keys have been wiped. */
void tui_msg_wipe(void){
    crypto_wipe(tui_msgs, sizeof tui_msgs);
    tui_msg_count = 0;
    tui_msg_start = 0;
}

/* Append a message to the ring buffer, overwriting the oldest if full.
 *
 * The slot is wiped before writing so that a short message replacing a
 * long one does not leave stale plaintext in the unused tail of the
 * text[] field.  Without this, snprintf null-terminates at the new
 * length but the old bytes beyond the null remain readable in RAM.
 * Example: "this is a secret plan" (22 bytes) overwritten by "hi" would
 * leave "hi\0s is a secret plan" in memory -- 19 bytes of old plaintext. */
void tui_msg_add(enum tui_sender who, const char *text){
    char t[16];
    int idx;
    ts(t, sizeof t);
    if (tui_msg_count < TUI_MSG_MAX){
        idx = tui_msg_count++;
    } else {
        idx = tui_msg_start;
        tui_msg_start = (tui_msg_start + 1) % TUI_MSG_MAX;
    }
    crypto_wipe(&tui_msgs[idx], sizeof tui_msgs[idx]);
    snprintf(tui_msgs[idx].ts, sizeof tui_msgs[idx].ts, "%s", t);
    tui_msgs[idx].who = who;
    snprintf(tui_msgs[idx].text, sizeof tui_msgs[idx].text, "%s", text);
}

/* ---- terminal size query ------------------------------------------------ */

/* Query the current terminal dimensions in columns (w) and rows (h).
 * Called before every full redraw so the layout adapts to resizes.
 * Falls back to 80x24 (the classic VT100 default) if the query fails. */
void tui_get_size(int *w, int *h){
#ifndef _WIN32
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0){
        *w = ws.ws_col;
        *h = ws.ws_row;
    } else {
        *w = 80; *h = 24;
    }
#else
    CONSOLE_SCREEN_BUFFER_INFO ci;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &ci)){
        *w = ci.srWindow.Right - ci.srWindow.Left + 1;
        *h = ci.srWindow.Bottom - ci.srWindow.Top + 1;
    } else {
        *w = 80; *h = 24;
    }
#endif
}

/* ---- drawing primitives -------------------------------------------------
 *
 * Each draw function writes to a specific region of the screen using
 * cursor-positioning escape sequences.  The screen is never scrolled;
 * we overwrite fixed rows in place.  This avoids scroll-related flicker
 * and lets us maintain the box border around the entire window.
 *
 * All drawing is done by the main thread, never from signal handlers. */

/* Draw a horizontal border line at the given row.
 * left_ch / right_ch select the corner character:
 *   1 = top corner (┌/┐), 2 = tee (├/┤), 3 = bottom corner (└/┘). */
void tui_draw_hline(int row, int left_ch, int right_ch){
    int i;
    TUI_GOTO(row, 1);
    printf("%s", TUI_COLOR_DIM);
    if (left_ch == 1) printf("\xe2\x94\x8c");
    else if (left_ch == 2) printf("\xe2\x94\x9c");
    else printf("\xe2\x94\x94");
    for (i = 1; i < tui_w - 1; i++) printf("\xe2\x94\x80");
    if (right_ch == 1) printf("\xe2\x94\x90");
    else if (right_ch == 2) printf("\xe2\x94\xa4");
    else printf("\xe2\x94\x98");
    printf("%s", TUI_COLOR_RESET);
}

/* Draw the title bar (row 1): "┌── SimpleCipher ────────────────────┐" */
void tui_draw_title(void){
    int i;
    TUI_GOTO(1, 1);
    TUI_CLEAR_LINE();
    printf("%s\xe2\x94\x8c\xe2\x94\x80 %sSimpleCipher%s ",
           TUI_COLOR_DIM, TUI_COLOR_RESET, TUI_COLOR_DIM);
    for (i = 16; i < tui_w - 1; i++) printf("\xe2\x94\x80");
    printf("\xe2\x94\x90%s", TUI_COLOR_RESET);
}

/* Draw the status bar (row 2): connection state and instructions. */
void tui_draw_status(const char *status){
    int max_len = tui_w - 4;
    TUI_GOTO(2, 1);
    TUI_CLEAR_LINE();
    printf("%s\xe2\x94\x82%s %s%-*.*s%s %s\xe2\x94\x82%s",
           TUI_COLOR_DIM, TUI_COLOR_RESET,
           TUI_COLOR_GREEN, max_len, max_len, status, TUI_COLOR_RESET,
           TUI_COLOR_DIM, TUI_COLOR_RESET);
}

/* Render the message area (rows 4 through H-2).
 *
 * Shows the most recent messages that fit on screen, reading from the
 * ring buffer.  Each line is formatted as:
 *   │ [HH:MM:SS] label: message text                              │
 * Colour-codes by sender: cyan for peer, yellow for system, default for self.
 * Unfilled rows below the last message are drawn as empty bordered lines. */
void tui_draw_messages(void){
    int msg_rows = tui_h - 5;
    int total = tui_msg_count < TUI_MSG_MAX ? tui_msg_count : TUI_MSG_MAX;
    int start_msg = total > msg_rows ? total - msg_rows : 0;
    int row = 4;
    int i;
    int max_text = tui_w - 22;

    if (max_text < 1) max_text = 1;

    for (i = start_msg; i < total && row <= tui_h - 2; i++, row++){
        int idx = (tui_msg_start + i) % TUI_MSG_MAX;
        const char *color = "";
        const char *label = "";

        TUI_GOTO(row, 1);
        TUI_CLEAR_LINE();

        switch (tui_msgs[idx].who){
            case TUI_ME:     color = "";              label = "  me"; break;
            case TUI_PEER:   color = TUI_COLOR_CYAN;  label = "peer"; break;
            case TUI_SYSTEM: color = TUI_COLOR_YELLOW; label = " sys"; break;
        }

        printf("%s\xe2\x94\x82%s [%s] %s%s%s: %-*.*s %s\xe2\x94\x82%s",
               TUI_COLOR_DIM, TUI_COLOR_RESET,
               tui_msgs[idx].ts,
               color, label, TUI_COLOR_RESET,
               max_text, max_text, tui_msgs[idx].text,
               TUI_COLOR_DIM, TUI_COLOR_RESET);
    }
    for (; row <= tui_h - 2; row++){
        TUI_GOTO(row, 1);
        TUI_CLEAR_LINE();
        printf("%s\xe2\x94\x82%s%*s%s\xe2\x94\x82%s",
               TUI_COLOR_DIM, TUI_COLOR_RESET,
               tui_w - 2, "",
               TUI_COLOR_DIM, TUI_COLOR_RESET);
    }
}

/* Draw the input line (bottom row): "└ > typed text here              ┘"
 *
 * If the typed text is longer than the visible area, only the rightmost
 * portion is shown (the view scrolls left as the user types).  The cursor
 * is re-shown and positioned at the end of the visible text so the user
 * can see where they are typing. */
void tui_draw_input(const char *line, size_t len){
    int max_input = tui_w - 6;
    int show_start = (int)len > max_input ? (int)len - max_input : 0;
    int visible_len = (int)len - show_start;
    int pad = max_input - visible_len;
    if (pad < 0) pad = 0;
    TUI_GOTO(tui_h, 1);
    TUI_CLEAR_LINE();
    printf("%s\xe2\x94\x94%s > %.*s%*s%s\xe2\x94\x98%s",
           TUI_COLOR_DIM, TUI_COLOR_RESET,
           visible_len, line + show_start,
           pad, "",
           TUI_COLOR_DIM, TUI_COLOR_RESET);
    printf("\033[?25h");
    TUI_GOTO(tui_h, 4 + visible_len);
    fflush(stdout);
}

/* Full-screen redraw: title, status, separators, messages, input.
 * Called on startup, terminal resize, and when a message arrives.
 * Hides the cursor during drawing to prevent flicker, then re-shows it
 * at the input position when done. */
void tui_draw_screen(const char *status, const char *line, size_t line_len){
    tui_get_size(&tui_w, &tui_h);
    if (tui_w < 40 || tui_h < 10){
        printf("\033[2J");
        TUI_GOTO(1, 1);
        printf("Terminal too small (need 40x10)");
        fflush(stdout);
        return;
    }
    printf("\033[?25l");
    tui_draw_title();
    tui_draw_status(status);
    tui_draw_hline(3, 2, 2);
    tui_draw_messages();
    tui_draw_hline(tui_h - 1, 2, 2);
    tui_draw_input(line, line_len);
}

/* Show a centred status message (e.g. "Connecting to host:port ...").
 * Used during the handshake phase before the chat UI is active. */
void tui_status_screen(const char *line1, const char *line2){
    int cy;
    tui_get_size(&tui_w, &tui_h);
    printf("\033[2J");
    tui_draw_title();
    cy = tui_h / 2 - 1;
    TUI_GOTO(cy, (tui_w - (int)strlen(line1)) / 2);
    printf("%s", line1);
    if (line2 && line2[0]){
        TUI_GOTO(cy + 1, (tui_w - (int)strlen(line2)) / 2);
        printf("%s%s%s", TUI_COLOR_DIM, line2, TUI_COLOR_RESET);
    }
    tui_draw_hline(tui_h, 3, 3);
    fflush(stdout);
}

/* ---- TUI: safety code verification screen -------------------------------
 *
 * Display the SAS (Short Authentication String) in a centred prompt and
 * require the user to type the first 4 characters to confirm.
 *
 * This is the TUI equivalent of the CLI's "type first 4 chars" prompt.
 * The same security rationale applies: forcing the user to type part of
 * the code prevents blind muscle-memory confirmation (just pressing Enter)
 * which would defeat the purpose of the SAS entirely.
 *
 * Returns 1 if the user typed a matching code, 0 on mismatch or abort. */
int tui_sas_screen(const char *sas){
    char typed[5] = {0};
    int  pos = 0;
    int  cy;

    tui_get_size(&tui_w, &tui_h);
    cy = tui_h / 2 - 2;

    printf("\033[2J");
    tui_draw_title();

    TUI_GOTO(cy, (tui_w - 34) / 2);
    printf("Verify safety code with your peer:");

    TUI_GOTO(cy + 2, (tui_w - (int)strlen(sas)) / 2);
    printf("%s%s%s", TUI_COLOR_BCYAN, sas, TUI_COLOR_RESET);

    TUI_GOTO(cy + 4, (tui_w - 38) / 2);
    printf("Type first 4 characters to confirm: ");
    printf("\033[?25h");
    fflush(stdout);

    while (pos < 4 && g_running){
#ifndef _WIN32
        struct pollfd pfd = { STDIN_FILENO, POLLIN, 0 };
        int pr = poll(&pfd, 1, 250);
        if (pr <= 0) continue;
        unsigned char ch = 0;
        if (read(STDIN_FILENO, &ch, 1) != 1) continue;
#else
        INPUT_RECORD rec;
        DWORD nread = 0;
        HANDLE h_in = GetStdHandle(STD_INPUT_HANDLE);
        DWORD wr = WaitForSingleObject(h_in, 250);
        if (wr != WAIT_OBJECT_0) continue;
        if (!ReadConsoleInputA(h_in, &rec, 1, &nread)) continue;
        if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown) continue;
        unsigned char ch = (unsigned char)rec.Event.KeyEvent.uChar.AsciiChar;
#endif
        if (ch == 0x03 || ch == 0x04){
            crypto_wipe(typed, sizeof typed);
            return 0;
        }
        if (ch == 0x7F || ch == 0x08){
            if (pos > 0){
                pos--;
                typed[pos] = 0;
                printf("\b \b");
                fflush(stdout);
            }
            continue;
        }
        if (ch >= 0x20 && ch <= 0x7E){
            typed[pos++] = (char)ch;
            putchar(ch);
            fflush(stdout);
        }
    }

    if (!g_running){ crypto_wipe(typed, sizeof typed); return 0; }

    for (int i = 0; i < 4; i++){
        char a = typed[i], b = sas[i];
        if (a >= 'a' && a <= 'z') a -= 32;
        if (b >= 'a' && b <= 'z') b -= 32;
        if (a != b){
            TUI_GOTO(cy + 6, (tui_w - 20) / 2);
            printf("\033[31mCode mismatch!\033[0m");
            fflush(stdout);
            crypto_wipe(typed, sizeof typed);
            return 0;
        }
    }
    crypto_wipe(typed, sizeof typed);
    return 1;
}
