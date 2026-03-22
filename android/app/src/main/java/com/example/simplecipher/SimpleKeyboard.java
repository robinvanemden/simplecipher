package com.example.simplecipher;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;

/**
 * Custom in-app keyboard for SimpleCipher.
 *
 * WHY THIS EXISTS:
 * The Android system keyboard (IME) processes every keystroke the user types.
 * Even with IME_FLAG_NO_PERSONALIZED_LEARNING, the IME app still *receives*
 * each character — it just promises not to store it for prediction.  But:
 *
 *   1. We cannot verify that promise.  Third-party keyboards (SwiftKey, Gboard,
 *      etc.) are closed-source and may log keystrokes regardless of the flag.
 *   2. The IME runs in a separate process with its own memory space, so even if
 *      we wipe our EditText contents, the IME may retain a copy.
 *   3. Some keyboards sync typed text to the cloud for "backup" or "sync across
 *      devices" features — sending plaintext messages to a remote server.
 *
 * By building our own keyboard as a View inside the activity, keystrokes never
 * leave our process.  We inject characters directly into the EditText via
 * getText().insert(), completely bypassing the InputMethodService pipeline.
 * Combined with showSoftInputOnFocus="false" and InputMethodManager.hideSoftInput,
 * the system keyboard is never shown and never receives input.
 *
 * This is the standard approach used by banking apps, password managers, and
 * other security-sensitive Android applications.
 */
public class SimpleKeyboard extends LinearLayout {

    /** Mode for hex input (SAS verification code) */
    public static final int MODE_HEX  = 0;
    /** Mode for text input (chat messages) */
    public static final int MODE_TEXT  = 1;

    /* Colors — match the app's dark theme from colors.xml */
    private static final int COLOR_BG       = 0xFF1A1A1A;  // bg_surface
    private static final int COLOR_KEY      = 0xFF252525;  // bg_input
    private static final int COLOR_KEY_PRESSED = 0xFF353535;
    private static final int COLOR_TEXT     = 0xFFF0F0F0;  // text_primary
    private static final int COLOR_ACCENT   = 0xFF4DD0B0;  // accent

    private static final int KEY_HEIGHT_DP  = 48;
    private static final int KEY_SPACING_DP = 4;
    private static final int CORNER_RADIUS_DP = 6;

    /* Letter rows for the QWERTY layout */
    private static final String[] ROW_1 = {"q","w","e","r","t","y","u","i","o","p"};
    private static final String[] ROW_2 = {"a","s","d","f","g","h","j","k","l"};
    private static final String[] ROW_3 = {"z","x","c","v","b","n","m"};

    /* Number/symbol rows */
    private static final String[] SYM_ROW_1 = {"1","2","3","4","5","6","7","8","9","0"};
    private static final String[] SYM_ROW_2 = {"@","#","$","%","&","-","+","(",")"};
    private static final String[] SYM_ROW_3 = {"=","*","!","?","'",":",";","/"};

    /* Hex rows */
    private static final String[] HEX_ROW_1 = {"0","1","2","3","4","5","6","7"};
    private static final String[] HEX_ROW_2 = {"8","9","A","B","C","D","E","F"};

    private int mode = MODE_TEXT;
    private EditText target;
    private Runnable onSendListener;

    private boolean shifted = false;
    private boolean symbolLayer = false;

    /* Container for key rows — rebuilt when mode/layer changes */
    private LinearLayout keysContainer;

    /* Both constructors are needed: the single-arg one for programmatic
     * creation, and the two-arg one for XML layout inflation (Android's
     * LayoutInflater calls (Context, AttributeSet) when it sees
     * <com.example.simplecipher.SimpleKeyboard> in a layout XML). */
    public SimpleKeyboard(Context context) { this(context, null); }

    public SimpleKeyboard(Context context, android.util.AttributeSet attrs) {
        super(context, attrs);
        setOrientation(VERTICAL);
        setBackgroundColor(COLOR_BG);
        int pad = dp(KEY_SPACING_DP);
        setPadding(pad, pad * 2, pad, pad * 2);

        keysContainer = new LinearLayout(context);
        keysContainer.setOrientation(VERTICAL);
        addView(keysContainer, new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT));

        buildKeys();
    }

    /** Switch between MODE_HEX and MODE_TEXT. Rebuilds the keyboard layout. */
    public void setMode(int mode) {
        this.mode = mode;
        this.shifted = false;
        this.symbolLayer = false;
        buildKeys();
    }

    /** Set the EditText that receives keystrokes from this keyboard. */
    public void setTarget(EditText target) {
        this.target = target;
    }

    /** Set the callback invoked when the Send key is pressed. */
    public void setOnSendListener(Runnable listener) {
        this.onSendListener = listener;
    }

    /* ---- Key layout construction ----------------------------------------- */

    private void buildKeys() {
        keysContainer.removeAllViews();

        if (mode == MODE_HEX) {
            buildHexLayout();
        } else if (symbolLayer) {
            buildSymbolLayout();
        } else {
            buildLetterLayout();
        }
    }

    private void buildHexLayout() {
        addRow(HEX_ROW_1, 0, 0);
        addRow(HEX_ROW_2, 0, 0);

        /* Bottom row: dash and backspace */
        LinearLayout row = newRow();
        addSpacer(row, 2.5f);
        addCharKey(row, "-", 1f, false);
        addSpacer(row, 2f);
        addSpecialKey(row, "\u232B", 1f, this::doBackspace);  // ⌫
        addSpacer(row, 2.5f);
        keysContainer.addView(row);
    }

    private void buildLetterLayout() {
        /* Row 1: q w e r t y u i o p */
        addRow(ROW_1, 0, 0);

        /* Row 2: a s d f g h j k l (half-key offset) */
        addRow(ROW_2, 0.5f, 0.5f);

        /* Row 3: Shift z x c v b n m Backspace */
        LinearLayout row3 = newRow();
        addSpecialKey(row3, "\u21E7", 1.5f, this::doShift);  // ⇧
        for (String ch : ROW_3) {
            addCharKey(row3, ch, 1f, false);
        }
        addSpecialKey(row3, "\u232B", 1.5f, this::doBackspace);  // ⌫
        keysContainer.addView(row3);

        /* Row 4: 123 / space / Send */
        LinearLayout row4 = newRow();
        addSpecialKey(row4, "123", 1.5f, this::toggleSymbols);
        addCharKey(row4, " ", 5f, false);  // space bar
        addSpecialKey(row4, "Send", 2.5f, this::doSend);
        keysContainer.addView(row4);
    }

    private void buildSymbolLayout() {
        /* Row 1: 1 2 3 4 5 6 7 8 9 0 */
        addRow(SYM_ROW_1, 0, 0);

        /* Row 2: @ # $ % & - + ( ) */
        addRow(SYM_ROW_2, 0.5f, 0.5f);

        /* Row 3: = * ! ? ' : ; / Backspace */
        LinearLayout row3 = newRow();
        addSpecialKey(row3, " ", 1f, null);  // empty spacer styled as invisible
        for (String ch : SYM_ROW_3) {
            addCharKey(row3, ch, 1f, false);
        }
        addSpecialKey(row3, "\u232B", 1f, this::doBackspace);  // ⌫
        keysContainer.addView(row3);

        /* Row 4: abc / space / Send */
        LinearLayout row4 = newRow();
        addSpecialKey(row4, "abc", 1.5f, this::toggleSymbols);
        addCharKey(row4, " ", 5f, false);  // space bar
        addSpecialKey(row4, "Send", 2.5f, this::doSend);
        keysContainer.addView(row4);
    }

    /* ---- Row helpers ----------------------------------------------------- */

    /** Add a simple row of character keys with optional leading/trailing weight spacers. */
    private void addRow(String[] keys, float leadWeight, float trailWeight) {
        LinearLayout row = newRow();
        if (leadWeight > 0) addSpacer(row, leadWeight);
        for (String ch : keys) {
            addCharKey(row, ch, 1f, false);
        }
        if (trailWeight > 0) addSpacer(row, trailWeight);
        keysContainer.addView(row);
    }

    private LinearLayout newRow() {
        LinearLayout row = new LinearLayout(getContext());
        row.setOrientation(HORIZONTAL);
        row.setGravity(Gravity.CENTER);
        LayoutParams lp = new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(KEY_SPACING_DP);
        row.setLayoutParams(lp);
        return row;
    }

    /* ---- Key creation ---------------------------------------------------- */

    private void addCharKey(LinearLayout row, String label, float weight, boolean isAccent) {
        Button btn = makeKeyButton(label.equals(" ") ? "space" : label, isAccent);
        LayoutParams lp = new LayoutParams(0, dp(KEY_HEIGHT_DP), weight);
        lp.setMargins(dp(KEY_SPACING_DP / 2), 0, dp(KEY_SPACING_DP / 2), 0);
        btn.setLayoutParams(lp);

        btn.setOnClickListener(v -> {
            if (target == null) return;
            String ch = label;
            if (shifted && ch.length() == 1 && Character.isLetter(ch.charAt(0))) {
                ch = ch.toUpperCase();
                shifted = false;
                buildKeys();  // revert shift visual
            }
            int start = Math.max(target.getSelectionStart(), 0);
            target.getText().insert(start, ch);
        });
        row.addView(btn);
    }

    private void addSpecialKey(LinearLayout row, String label, float weight, Runnable action) {
        boolean isVisible = !label.trim().isEmpty();
        Button btn = makeKeyButton(label, true);

        /* Invisible spacer key — no background, no click */
        if (!isVisible) {
            btn.setBackgroundColor(Color.TRANSPARENT);
            btn.setEnabled(false);
        }

        LayoutParams lp = new LayoutParams(0, dp(KEY_HEIGHT_DP), weight);
        lp.setMargins(dp(KEY_SPACING_DP / 2), 0, dp(KEY_SPACING_DP / 2), 0);
        btn.setLayoutParams(lp);

        if (action != null && isVisible) {
            btn.setOnClickListener(v -> action.run());
        }
        row.addView(btn);
    }

    private void addSpacer(LinearLayout row, float weight) {
        View spacer = new View(getContext());
        LayoutParams lp = new LayoutParams(0, dp(KEY_HEIGHT_DP), weight);
        lp.setMargins(dp(KEY_SPACING_DP / 2), 0, dp(KEY_SPACING_DP / 2), 0);
        spacer.setLayoutParams(lp);
        row.addView(spacer);
    }

    /** Create a styled Button matching the app's dark theme. */
    private Button makeKeyButton(String label, boolean accent) {
        Button btn = new Button(getContext());
        btn.setText(label);
        btn.setTextColor(accent ? COLOR_ACCENT : COLOR_TEXT);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        btn.setAllCaps(false);
        btn.setPadding(0, 0, 0, 0);
        btn.setMinWidth(0);
        btn.setMinimumWidth(0);
        btn.setMinHeight(0);
        btn.setMinimumHeight(0);
        btn.setGravity(Gravity.CENTER);
        btn.setStateListAnimator(null);  // remove Material elevation animation

        /* Display shifted label if shift is active */
        if (shifted && label.length() == 1 && Character.isLetter(label.charAt(0))) {
            btn.setText(label.toUpperCase());
        }

        /* Rounded background with pressed state */
        btn.setBackground(makeKeyBackground());
        return btn;
    }

    /** Drawable: rounded rectangle with normal/pressed states. */
    private StateListDrawable makeKeyBackground() {
        StateListDrawable states = new StateListDrawable();

        GradientDrawable pressed = new GradientDrawable();
        pressed.setShape(GradientDrawable.RECTANGLE);
        pressed.setCornerRadius(dp(CORNER_RADIUS_DP));
        pressed.setColor(COLOR_KEY_PRESSED);

        GradientDrawable normal = new GradientDrawable();
        normal.setShape(GradientDrawable.RECTANGLE);
        normal.setCornerRadius(dp(CORNER_RADIUS_DP));
        normal.setColor(COLOR_KEY);

        states.addState(new int[]{android.R.attr.state_pressed}, pressed);
        states.addState(new int[]{}, normal);
        return states;
    }

    /* ---- Key actions ----------------------------------------------------- */

    private void doBackspace() {
        if (target == null) return;
        int cursor = target.getSelectionStart();
        if (cursor > 0) {
            target.getText().delete(cursor - 1, cursor);
        }
    }

    private void doShift() {
        shifted = !shifted;
        buildKeys();
    }

    private void toggleSymbols() {
        symbolLayer = !symbolLayer;
        buildKeys();
    }

    private void doSend() {
        if (onSendListener != null) {
            onSendListener.run();
        }
    }

    /* ---- Utility --------------------------------------------------------- */

    private int dp(int dp) {
        return (int) (dp * getResources().getDisplayMetrics().density + 0.5f);
    }
}
