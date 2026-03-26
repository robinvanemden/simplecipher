/*
 * tui.c — Shared TUI drawing code for SimpleCipher
 *
 * Implements the ring buffer, drawing primitives, and screens that are
 * shared between POSIX and Windows.  The platform-specific terminal
 * setup and event loops live in tui_posix.c and tui_win.c respectively.
 */

#include "tui.h"

#ifndef _WIN32
#    include <sys/ioctl.h>
#endif

/* ---- ring buffer state (extern declarations in tui.h) ------------------- */

struct tui_msg_entry tui_msgs[TUI_MSG_MAX];

int tui_msg_count = 0; /* total messages stored (up to TUI_MSG_MAX) */
int tui_msg_start = 0; /* index of oldest message in the ring */

int tui_w = 80, tui_h = 24; /* cached terminal dimensions */

/* ---- ring buffer operations --------------------------------------------- */

/* Wipe all plaintext messages from the ring buffer.
 * Called at session shutdown so chat history does not linger in RAM.
 * Without this, a core dump or memory forensics tool could recover the
 * entire conversation even though all crypto keys have been wiped. */
void tui_msg_wipe(void) {
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
void tui_msg_add(enum tui_sender who, const char *text) {
    char t[16];
    int  idx;
    ts(t, sizeof t);
    if (tui_msg_count < TUI_MSG_MAX) {
        idx = tui_msg_count++;
    } else {
        idx           = tui_msg_start;
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
void tui_get_size(int *w, int *h) {
#ifndef _WIN32
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        *w = ws.ws_col;
        *h = ws.ws_row;
    } else {
        *w = 80;
        *h = 24;
    }
#else
    CONSOLE_SCREEN_BUFFER_INFO ci;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &ci)) {
        *w = ci.srWindow.Right - ci.srWindow.Left + 1;
        *h = ci.srWindow.Bottom - ci.srWindow.Top + 1;
    } else {
        *w = 80;
        *h = 24;
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
void tui_draw_hline(int row, int left_ch, int right_ch) {
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
void tui_draw_title(void) {
    int i;
    TUI_GOTO(1, 1);
    TUI_CLEAR_LINE();
    printf("%s\xe2\x94\x8c\xe2\x94\x80 %sSimpleCipher%s ", TUI_COLOR_DIM, TUI_COLOR_RESET, TUI_COLOR_DIM);
    for (i = 16; i < tui_w - 1; i++) printf("\xe2\x94\x80");
    printf("\xe2\x94\x90%s", TUI_COLOR_RESET);
}

/* Draw the status bar (row 2): connection state and instructions. */
void tui_draw_status(const char *status) {
    int max_len = tui_w - 4;
    TUI_GOTO(2, 1);
    TUI_CLEAR_LINE();
    printf("%s\xe2\x94\x82%s %s%-*.*s%s %s\xe2\x94\x82%s", TUI_COLOR_DIM, TUI_COLOR_RESET, TUI_COLOR_GREEN, max_len,
           max_len, status, TUI_COLOR_RESET, TUI_COLOR_DIM, TUI_COLOR_RESET);
}

/* Render the message area (rows 4 through H-2).
 *
 * Shows the most recent messages that fit on screen, reading from the
 * ring buffer.  Each line is formatted as:
 *   │ [HH:MM:SS] label: message text                              │
 * Colour-codes by sender: cyan for peer, yellow for system, default for self.
 * Unfilled rows below the last message are drawn as empty bordered lines. */
void tui_draw_messages(void) {
    int max_row  = tui_h - 2;
    int total    = tui_msg_count < TUI_MSG_MAX ? tui_msg_count : TUI_MSG_MAX;
    int max_text = tui_w - 21;
    int i;

    if (max_text < 1) max_text = 1;

    /* First pass: count how many screen rows all messages need so we can
     * figure out which message to start from (bottom-aligned). */
    int total_rows = 0;
    for (i = 0; i < total; i++) {
        int idx      = (tui_msg_start + i) % TUI_MSG_MAX;
        int text_len = (int)strlen(tui_msgs[idx].text);
        int lines    = (text_len + max_text - 1) / max_text;
        if (lines < 1) lines = 1;
        total_rows += lines;
    }

    int msg_rows  = max_row - 4 + 1; /* available screen rows for messages */
    int start_msg = 0;
    /* Find the first message to display so that the last messages fit */
    {
        int acc = 0;
        for (i = total - 1; i >= 0; i--) {
            int idx      = (tui_msg_start + i) % TUI_MSG_MAX;
            int text_len = (int)strlen(tui_msgs[idx].text);
            int lines    = (text_len + max_text - 1) / max_text;
            if (lines < 1) lines = 1;
            if (acc + lines > msg_rows) {
                start_msg = i + 1;
                break;
            }
            acc += lines;
        }
    }

    int row = 4;

    for (i = start_msg; i < total && row <= max_row; i++) {
        int         idx   = (tui_msg_start + i) % TUI_MSG_MAX;
        const char *color = "";
        const char *label = "";

        switch (tui_msgs[idx].who) {
        case TUI_ME:
            color = "";
            label = "  me";
            break;
        case TUI_PEER:
            color = TUI_COLOR_CYAN;
            label = "peer";
            break;
        case TUI_SYSTEM:
            color = TUI_COLOR_YELLOW;
            label = " sys";
            break;
        }

        const char *text     = tui_msgs[idx].text;
        int         text_len = (int)strlen(text);
        int         offset   = 0;
        int         first    = 1;

        while (offset < text_len && row <= max_row) {
            int chunk = text_len - offset;
            if (chunk > max_text) chunk = max_text;

            TUI_GOTO(row, 1);
            TUI_CLEAR_LINE();

            if (first) {
                printf("%s\xe2\x94\x82%s [%s] %s%s%s: %-*.*s %s\xe2\x94\x82%s", TUI_COLOR_DIM, TUI_COLOR_RESET,
                       tui_msgs[idx].ts, color, label, TUI_COLOR_RESET, max_text, chunk, text + offset, TUI_COLOR_DIM,
                       TUI_COLOR_RESET);
                first = 0;
            } else {
                /* 18 = strlen(" [HH:MM:SS] label: ") — matches the prefix width */
                printf("%s\xe2\x94\x82%s %*s%-*.*s %s\xe2\x94\x82%s", TUI_COLOR_DIM, TUI_COLOR_RESET, 18, "", max_text,
                       chunk, text + offset, TUI_COLOR_DIM, TUI_COLOR_RESET);
            }
            offset += chunk;
            row++;
        }
        /* Handle empty messages (no text at all) */
        if (text_len == 0 && first) {
            TUI_GOTO(row, 1);
            TUI_CLEAR_LINE();
            printf("%s\xe2\x94\x82%s [%s] %s%s%s: %-*s %s\xe2\x94\x82%s", TUI_COLOR_DIM, TUI_COLOR_RESET,
                   tui_msgs[idx].ts, color, label, TUI_COLOR_RESET, max_text, "", TUI_COLOR_DIM, TUI_COLOR_RESET);
            row++;
        }
    }
    for (; row <= max_row; row++) {
        TUI_GOTO(row, 1);
        TUI_CLEAR_LINE();
        printf("%s\xe2\x94\x82%s%*s%s\xe2\x94\x82%s", TUI_COLOR_DIM, TUI_COLOR_RESET, tui_w - 2, "", TUI_COLOR_DIM,
               TUI_COLOR_RESET);
    }
}

/* Draw the input line (bottom row): "└ > typed text here              ┘"
 *
 * If the typed text is longer than the visible area, only the rightmost
 * portion is shown (the view scrolls left as the user types).  The cursor
 * is re-shown and positioned at the end of the visible text so the user
 * can see where they are typing. */
void tui_draw_input(const char *line, size_t len) {
    int max_input   = tui_w - 5;
    int show_start  = (int)len > max_input ? (int)len - max_input : 0;
    int visible_len = (int)len - show_start;
    int pad         = max_input - visible_len;
    if (pad < 0) pad = 0;
    TUI_GOTO(tui_h, 1);
    TUI_CLEAR_LINE();
    printf("%s\xe2\x94\x94%s > %.*s%*s%s\xe2\x94\x98%s", TUI_COLOR_DIM, TUI_COLOR_RESET, visible_len, line + show_start,
           pad, "", TUI_COLOR_DIM, TUI_COLOR_RESET);
    printf("\033[?25h"); /* show cursor */
    printf("\033[1 q");  /* block cursor (more visible than line) */
    TUI_GOTO(tui_h, 5 + visible_len);
    fflush(stdout);
}

/* Full-screen redraw: title, status, separators, messages, input.
 * Called on startup, terminal resize, and when a message arrives.
 * Hides the cursor during drawing to prevent flicker, then re-shows it
 * at the input position when done. */
void tui_draw_screen(const char *status, const char *line, size_t line_len) {
    tui_get_size(&tui_w, &tui_h);
    if (tui_w < 40 || tui_h < 10) {
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
void tui_status_screen(const char *line1, const char *line2) {
    int cy;
    tui_get_size(&tui_w, &tui_h);
    if (tui_w < 40 || tui_h < 10) {
        printf("\033[2J\033[H");
        printf("Terminal too small (need 40x10)\n");
        return;
    }
    printf("\033[2J");
    tui_draw_title();
    cy = tui_h / 2 - 1;
    TUI_GOTO(cy, (tui_w - (int)strlen(line1)) / 2);
    printf("%s", line1);
    if (line2 && line2[0]) {
        TUI_GOTO(cy + 1, (tui_w - (int)strlen(line2)) / 2);
        printf("%s%s%s", TUI_COLOR_DIM, line2, TUI_COLOR_RESET);
    }
    tui_draw_hline(tui_h, 3, 3);
    fflush(stdout);
}

/* Show the listen/waiting screen with local IP addresses so the user
 * can tell their peer which command to run. */
void tui_listen_screen(const char *port, const char *ips) {
    int cy;
    tui_get_size(&tui_w, &tui_h);
    if (tui_w < 40 || tui_h < 10) {
        printf("\033[2J\033[H");
        printf("Terminal too small (need 40x10)\n");
        return;
    }
    printf("\033[2J");
    tui_draw_title();

    /* Count IP lines */
    int nips = 0;
    if (ips && ips[0]) {
        nips = 1;
        for (const char *c = ips; *c; c++)
            if (*c == '\n') nips++;
    }

    /* Center vertically: title(1) + "Listening"(1) + blank(1) + "Tell peer"(1)
     * + ip lines + blank(1) + "Waiting..." */
    int block_h = 4 + nips + 1;
    cy          = (tui_h - block_h) / 2;
    if (cy < 3) cy = 3;

    /* "Listening on port XXXX" */
    {
        char msg[80];
        snprintf(msg, sizeof msg, "Listening on port %s", port);
        TUI_GOTO(cy, (tui_w - (int)strlen(msg)) / 2);
        printf("%s", msg);
    }
    cy += 2;

    /* "Tell your peer to run:" + IP list */
    if (nips > 0) {
        const char *label = "Tell your peer to run:";
        TUI_GOTO(cy, (tui_w - (int)strlen(label)) / 2);
        printf("%s%s%s", TUI_COLOR_DIM, label, TUI_COLOR_RESET);
        cy++;

        /* Print each IP as a connect command */
        const char *p = ips;
        while (*p) {
            const char *nl = p;
            while (*nl && *nl != '\n') nl++;
            char cmd[128];
            int  cmdlen = snprintf(cmd, sizeof cmd, "simplecipher connect %.*s %s", (int)(nl - p), p, port);
            TUI_GOTO(cy, (tui_w - cmdlen) / 2);
            printf("%s%s%s", TUI_COLOR_CYAN, cmd, TUI_COLOR_RESET);
            cy++;
            p = *nl ? nl + 1 : nl;
        }
        cy++;
    }

    /* "Waiting for connection..." */
    {
        const char *wait = "Waiting for connection...";
        TUI_GOTO(cy, (tui_w - (int)strlen(wait)) / 2);
        printf("%s%s%s", TUI_COLOR_DIM, wait, TUI_COLOR_RESET);
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
int tui_sas_screen(const char *sas) {
    int  sas_len   = (int)strlen(sas); /* 9 for "XXXX-XXXX" */
    char typed[20] = {0};
    int  pos       = 0;
    int  cy;

    tui_get_size(&tui_w, &tui_h);
    if (tui_w < 40 || tui_h < 14) {
        printf("\033[2J\033[H");
        printf("Terminal too small (need 40x14)\n");
        return 0;
    }
    cy = tui_h / 2 - 6;
    if (cy < 3) cy = 3;

    printf("\033[2J");
    tui_draw_title();

    {
        const char *hdr = "SAFETY CODE";
        TUI_GOTO(cy, (tui_w - (int)strlen(hdr)) / 2);
        printf("%s%s%s", TUI_COLOR_GREEN, hdr, TUI_COLOR_RESET);
    }

    TUI_GOTO(cy + 2, (tui_w - (int)strlen(sas)) / 2);
    printf("%s%s%s", TUI_COLOR_BCYAN, sas, TUI_COLOR_RESET);

    {
        const char *l1 = "Call or meet your peer and compare this code.";
        const char *l2 = "If it matches, type the full code to confirm.";
        const char *l3 = "If not, press Ctrl+C -- someone is intercepting.";
        TUI_GOTO(cy + 4, (tui_w - (int)strlen(l1)) / 2);
        printf("%s%s%s", TUI_COLOR_DIM, l1, TUI_COLOR_RESET);
        TUI_GOTO(cy + 5, (tui_w - (int)strlen(l2)) / 2);
        printf("%s%s%s", TUI_COLOR_DIM, l2, TUI_COLOR_RESET);
        TUI_GOTO(cy + 6, (tui_w - (int)strlen(l3)) / 2);
        printf("%s%s%s", TUI_COLOR_DIM, l3, TUI_COLOR_RESET);
        const char *l4 = "Fingerprint = identity (pre-shared).";
        const char *l5 = "Safety code = this session (compare now).";
        TUI_GOTO(cy + 8, (tui_w - (int)strlen(l4)) / 2);
        printf("%s%s%s", TUI_COLOR_DIM, l4, TUI_COLOR_RESET);
        TUI_GOTO(cy + 9, (tui_w - (int)strlen(l5)) / 2);
        printf("%s%s%s", TUI_COLOR_DIM, l5, TUI_COLOR_RESET);
    }

    {
        const char *prompt = "Confirm: ";
        TUI_GOTO(cy + 11, (tui_w - (int)strlen(prompt) - sas_len) / 2);
        printf("%s", prompt);
    }
    printf("\033[?25h");
    printf("\033[1 q"); /* block cursor */
    fflush(stdout);

    while (pos < (int)sizeof(typed) - 1 && g_running) {
#ifndef _WIN32
        struct pollfd pfd = {STDIN_FILENO, POLLIN, 0};
        int           pr  = poll(&pfd, 1, 250);
        if (pr <= 0) continue;
        unsigned char ch = 0;
        if (read(STDIN_FILENO, &ch, 1) != 1) continue;
#else
        INPUT_RECORD rec;
        DWORD        nread = 0;
        HANDLE       h_in  = GetStdHandle(STD_INPUT_HANDLE);
        DWORD        wr    = WaitForSingleObject(h_in, 250);
        if (wr != WAIT_OBJECT_0) continue;
        if (!ReadConsoleInputA(h_in, &rec, 1, &nread)) continue;
        if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown) continue;
        unsigned char ch = (unsigned char)rec.Event.KeyEvent.uChar.AsciiChar;
#endif
        if (ch == 0x03 || ch == 0x04) {
            crypto_wipe(typed, sizeof typed);
            return 0;
        }
        if (ch == 0x7F || ch == 0x08) {
            if (pos > 0) {
                pos--;
                typed[pos] = 0;
                printf("\b \b");
                fflush(stdout);
            }
            continue;
        }
        /* Enter submits whatever has been typed (must have at least 4 chars
         * to prevent accidental empty submits). */
        if ((ch == '\r' || ch == '\n') && pos >= 4) break;
        if (ch >= 0x20 && ch <= 0x7E) {
            typed[pos++] = (char)ch;
            putchar(ch);
            fflush(stdout);
        }
    }
    typed[pos] = '\0';

    if (!g_running) {
        crypto_wipe(typed, sizeof typed);
        return 0;
    }

    /* Normalize both strings: strip dashes and uppercase, then compare.
     * This accepts "A3F2-91BC", "A3F291BC", "a3f2-91bc" etc. — the user
     * does not need to remember whether the dash is part of the code. */
    {
        char norm_typed[20] = {0}, norm_sas[20] = {0};
        int  ti = 0, si = 0;
        for (int i = 0; typed[i] && ti < (int)sizeof(norm_typed) - 1; i++) {
            char c = typed[i];
            if (c == '-') continue;
            if (c >= 'a' && c <= 'z') c -= 32;
            norm_typed[ti++] = c;
        }
        for (int i = 0; sas[i] && si < (int)sizeof(norm_sas) - 1; i++) {
            char c = sas[i];
            if (c == '-') continue;
            if (c >= 'a' && c <= 'z') c -= 32;
            norm_sas[si++] = c;
        }
        int ok = (ti == si && ct_compare((const uint8_t *)norm_typed, (const uint8_t *)norm_sas, (size_t)ti) == 0);
        crypto_wipe(norm_typed, sizeof norm_typed);
        crypto_wipe(norm_sas, sizeof norm_sas);
        if (!ok) {
            TUI_GOTO(cy + 10, (tui_w - 20) / 2);
            printf("\033[31mCode mismatch!\033[0m");
            fflush(stdout);
            crypto_wipe(typed, sizeof typed);
            return 0;
        }
    }
    crypto_wipe(typed, sizeof typed);
    return 1;
}
