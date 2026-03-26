package com.example.simplecipher;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.method.ScrollingMovementMethod;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import java.io.UnsupportedEncodingException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Chat screen for SimpleCipher.
 *
 * <p>Communicates with the native session thread via two JNI methods: - nativeStart(mode, host,
 * port, callback) — spawns the thread - nativePostCommand(cmd, payload) — writes to the command
 * pipe
 *
 * <p>All results come back through the NativeCallback interface methods, which are called FROM the
 * native thread — every callback posts its UI work to the main thread via uiHandler.
 */
public class ChatActivity extends Activity implements NativeCallback {

  static {
    System.loadLibrary("simplecipher");
  }

  /* Native methods. */
  private native int nativeStart(
      int mode, String host, int port, String socks5Proxy, NativeCallback callback);

  private native boolean nativePostCommand(int cmd, byte[] payload);

  private native void nativeStop(); /* out-of-band forced teardown */

  /* Command constants — must match jni_bridge.c */
  private static final int CMD_SEND = 0x01;
  private static final int CMD_CONFIRM_SAS = 0x02;

  private final Handler uiHandler = new Handler(Looper.getMainLooper());

  /* UI elements */
  private TextView statusText;
  private LinearLayout sasLayout;
  private TextView sasCodeText;
  private EditText sasInput;
  private Button sasConfirmBtn;
  private LinearLayout chatLayout;
  private TextView chatLog;
  private EditText chatInput;
  private Button sendBtn;
  private SimpleKeyboard inAppKeyboard;

  /* The SAS code received from native, stored for verification. */
  private String pendingSas = null;

  /* Pause flag: when true, appendChat() drops messages to avoid
   * leaking plaintext into the Java heap while the app is backgrounded. */
  private boolean paused = false;
  /* Message waiting for onSendResult confirmation before display. */
  private String pendingSendMsg = null;
  /* True after onConnected, false after onDisconnected/onStop. */
  private boolean sessionLive = false;

  /**
   * True if the peer fingerprint was pre-verified by native during handshake. Set from native
   * thread via onPeerFingerprintReady, read on UI thread.
   */
  private volatile boolean fingerprintVerified = false;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    /* FLAG_SECURE prevents screenshots and screen recording. */
    getWindow()
        .setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
    /* HIDE_OVERLAY_WINDOWS prevents other apps from drawing on top of
     * this activity (tapjacking, screen recording overlays). */
    if (android.os.Build.VERSION.SDK_INT >= 31) getWindow().setHideOverlayWindows(true);

    setContentView(R.layout.activity_chat);

    statusText = findViewById(R.id.statusText);
    sasLayout = findViewById(R.id.sasLayout);
    sasCodeText = findViewById(R.id.sasCodeText);
    sasInput = findViewById(R.id.sasInput);
    sasConfirmBtn = findViewById(R.id.sasConfirmBtn);
    chatLayout = findViewById(R.id.chatLayout);
    chatLog = findViewById(R.id.chatLog);
    chatInput = findViewById(R.id.chatInput);

    /* Suppress the system keyboard on sensitive inputs.  Set
     * programmatically because the XML attribute is not reliably
     * available across all build tool versions. */
    sasInput.setShowSoftInputOnFocus(false);
    chatInput.setShowSoftInputOnFocus(false);
    sendBtn = findViewById(R.id.sendBtn);

    /* --- Custom in-app keyboard setup ---
     *
     * We use our own SimpleKeyboard instead of the system IME so that
     * keystrokes never leave our process.  The system keyboard (Gboard,
     * SwiftKey, etc.) runs in a separate process and may log, cache, or
     * sync keystrokes despite IME_FLAG_NO_PERSONALIZED_LEARNING.
     *
     * Defence in depth: we still set the no-learn flag (some system
     * components check it), but the real protection is that we hide the
     * IME entirely and inject text via SimpleKeyboard. */
    int noLearn = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING;
    sasInput.setImeOptions(sasInput.getImeOptions() | noLearn);
    chatInput.setImeOptions(chatInput.getImeOptions() | noLearn);

    /* Suppress the system soft keyboard at the window level */
    getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

    inAppKeyboard = findViewById(R.id.inAppKeyboard);
    inAppKeyboard.setOnSendListener(this::sendMessage);

    /* When the chat input gains focus, show the in-app keyboard in TEXT
     * mode and forcibly dismiss the system IME.  The showSoftInputOnFocus
     * XML attribute prevents the IME from appearing on touch, but we also
     * call hideSoftInputFromWindow as belt-and-suspenders — some custom
     * ROMs and older devices ignore the XML attribute. */
    chatInput.setOnFocusChangeListener(
        (v, hasFocus) -> {
          if (hasFocus) {
            hideSystemKeyboard(chatInput);
            inAppKeyboard.setMode(SimpleKeyboard.MODE_TEXT);
            inAppKeyboard.setTarget(chatInput);
            inAppKeyboard.setVisibility(View.VISIBLE);
          }
        });

    /* Same for the SAS input: show HEX keyboard when focused */
    sasInput.setOnFocusChangeListener(
        (v, hasFocus) -> {
          if (hasFocus) {
            hideSystemKeyboard(sasInput);
            inAppKeyboard.setMode(SimpleKeyboard.MODE_HEX);
            inAppKeyboard.setTarget(sasInput);
            inAppKeyboard.setVisibility(View.VISIBLE);
          }
        });

    chatLog.setMovementMethod(new ScrollingMovementMethod());

    String mode = getIntent().getStringExtra("mode");
    String host = getIntent().getStringExtra("host");
    int port = getIntent().getIntExtra("port", 7777);
    String socks5Proxy = getIntent().getStringExtra("socks5_proxy");

    boolean isConnect = "connect".equals(mode);

    if (isConnect) {
      if (socks5Proxy != null && !socks5Proxy.isEmpty()) {
        statusText.setText("Connecting via SOCKS5 to " + host + ":" + port + " ...");
      } else {
        statusText.setText("Connecting to " + host + ":" + port + " ...");
      }
    } else {
      String ips = getLocalIps();
      if (ips.isEmpty()) {
        statusText.setText("Listening on port " + port + "\nNo network interfaces found");
      } else {
        statusText.setText("Listening on port " + port + "\n\nTell your peer to run:\n" + ips);
      }
    }

    /* Wire send button + Enter key (they post CMD_SEND to the pipe) */
    sendBtn.setOnClickListener(v -> sendMessage());
    chatInput.setOnEditorActionListener(
        (tv, actionId, event) -> {
          sendMessage();
          return true;
        });

    /* Start the native session thread.
     * mode: 0 = listen, 1 = connect.  Returns immediately. */
    int nativeMode = isConnect ? 1 : 0;
    int rc = nativeStart(nativeMode, host, port, socks5Proxy, this);
    if (rc != 0) {
      Toast.makeText(this, "Failed to start session", Toast.LENGTH_LONG).show();
      finish();
    }
  }

  /* ---- Send message --------------------------------------------------- */

  private void sendMessage() {
    if (!sessionLive) return; /* session dead — ignore Enter key */
    String msg = chatInput.getText().toString().trim();
    if (msg.isEmpty()) return;
    chatInput.setText("");

    try {
      byte[] payload = msg.getBytes("UTF-8");
      boolean ok = nativePostCommand(CMD_SEND, payload);
      /* Do NOT show the message here — the pipe write succeeding only
       * means the bytes reached the native thread's command buffer.
       * The native thread might still reject it (e.g., frame_build fails
       * because the message exceeds MAX_MSG_RATCHET after a ratchet step).
       * The message is shown later when onSendResult(true) arrives.
       *
       * Disable input until onSendResult returns to prevent the user from
       * queuing a second message that would overwrite pendingSendMsg.
       * This ensures exactly one in-flight message at a time. */
      if (ok) {
        pendingSendMsg = msg;
        sendBtn.setEnabled(false);
        chatInput.setEnabled(false);
      } else {
        appendChat("system", "[send failed — pipe full, try again]");
      }
    } catch (UnsupportedEncodingException e) {
      appendChat("system", "[encoding error]");
    }
  }

  /* ---- NativeCallback implementation ---------------------------------- */
  /* All methods are called FROM the native thread.  UI work is posted
   * to the main thread via uiHandler. */

  @Override
  public void onConnected() {
    uiHandler.post(
        () -> {
          statusText.setText("Connected. Performing handshake...");
          sessionLive = true;
        });
  }

  @Override
  public void onConnectionFailed(String reason) {
    uiHandler.post(
        () -> {
          Toast.makeText(this, reason, Toast.LENGTH_LONG).show();
          finish();
        });
  }

  @Override
  public void onSasReady(String code) {
    uiHandler.post(
        () -> {
          /* Do not populate sensitive UI while paused — onPause() has
           * already wiped the widgets and nativeStop() may have fired. */
          if (paused) return;

          pendingSas = code;
          if (fingerprintVerified) {
            statusText.setText("\u2705 Fingerprint verified \u2014 confirm safety code to proceed");
          } else {
            statusText.setText("Verify safety code with your peer");
          }
          sasCodeText.setText(code);
          sasLayout.setVisibility(View.VISIBLE);

          /* Show the hex keyboard for SAS input and give it focus */
          inAppKeyboard.setMode(SimpleKeyboard.MODE_HEX);
          inAppKeyboard.setTarget(sasInput);
          inAppKeyboard.setVisibility(View.VISIBLE);
          sasInput.requestFocus();
          hideSystemKeyboard(sasInput);

          /* Enter key on SAS input triggers the confirm button */
          sasInput.setOnEditorActionListener(
              (v, a, e) -> {
                sasConfirmBtn.performClick();
                return true;
              });

          sasConfirmBtn.setOnClickListener(
              v -> {
                /* Normalize: strip dashes and uppercase.  Accepts "A3F2-91BC",
                 * "A3F291BC", "a3f291bc" etc.  Full comparison ensures the user
                 * verifies all 32 bits of the SAS, not just the first 16. */
                String typed =
                    sasInput.getText().toString().trim().replace("-", "").toUpperCase(Locale.ROOT);
                String expected = pendingSas.replace("-", "").toUpperCase(Locale.ROOT);

                if (!typed.equals(expected)) {
                  Toast.makeText(this, "Code mismatch \u2014 aborting", Toast.LENGTH_LONG).show();
                  nativeStop();
                  finish();
                  return;
                }

                /* SAS verified — tell native thread, transition to chat UI.
                 * If the pipe write fails (session already torn down),
                 * don't transition to chat — the session is gone. */
                if (!nativePostCommand(CMD_CONFIRM_SAS, null)) {
                  Toast.makeText(ChatActivity.this, "Session ended", Toast.LENGTH_SHORT).show();
                  finish();
                  return;
                }

                sasInput.setText("");
                sasCodeText.setText("");
                pendingSas = null;
                sasLayout.setVisibility(View.GONE);
                chatLayout.setVisibility(View.VISIBLE);
                statusText.setText("\uD83D\uDD12 Secure session active");
                statusText.setTextColor(0xFF4DD0B0);

                /* Switch keyboard to text mode for chat input */
                inAppKeyboard.setMode(SimpleKeyboard.MODE_TEXT);
                inAppKeyboard.setTarget(chatInput);
                chatInput.requestFocus();
                hideSystemKeyboard(chatInput);
              });
        });
  }

  @Override
  public void onPeerFingerprintReady(String fingerprint, boolean verified) {
    /* Set directly — this is a simple boolean write with no UI dependency.
     * The native thread calls this BEFORE onSasReady, and Android's Handler
     * queue is strictly FIFO, so the onSasReady handler will see the
     * updated value. Using a volatile field instead of uiHandler.post
     * makes the ordering guarantee explicit. */
    fingerprintVerified = verified;
  }

  @Override
  public void onHandshakeFailed(String reason) {
    uiHandler.post(
        () -> {
          Toast.makeText(this, "Handshake failed: " + reason, Toast.LENGTH_LONG).show();
          finish();
        });
  }

  @Override
  public void onMessageReceived(String text) {
    uiHandler.post(() -> appendChat("peer", text));
  }

  @Override
  public void onSendResult(boolean ok) {
    uiHandler.post(
        () -> {
          if (ok && pendingSendMsg != null) {
            appendChat("me", pendingSendMsg);
          } else if (!ok) {
            appendChat("system", "[send failed]");
          }
          pendingSendMsg = null;
          /* Re-enable input — one message confirmed, user can send the next. */
          sendBtn.setEnabled(true);
          chatInput.setEnabled(true);
        });
  }

  @Override
  public void onDisconnected(String reason) {
    uiHandler.post(
        () -> {
          appendChat("system", reason);
          appendChat("system", "Session ended. Keys wiped. Nothing was stored to disk.");
          sendBtn.setEnabled(false);
          chatInput.setEnabled(false); /* block Enter key too, not just button */
          sessionLive = false;
        });
  }

  /* ---- Chat log ------------------------------------------------------- */

  private void appendChat(String who, String msg) {
    /* Do not write plaintext to the UI while paused.  onPause() wipes
     * the widgets; allowing callbacks to repopulate chatLog after the
     * wipe would leak plaintext into the Java heap while the app is
     * backgrounded. */
    if (paused) return;
    String ts = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
    String line = "[" + ts + "] " + who + ": " + msg + "\n";
    SpannableString spannable = new SpannableString(line);
    int color;
    if ("me".equals(who)) {
      color = getColor(R.color.accent);
    } else if ("peer".equals(who)) {
      color = getColor(R.color.text_primary);
    } else {
      color = getColor(R.color.text_secondary);
    }
    spannable.setSpan(
        new ForegroundColorSpan(color), 0, spannable.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
    chatLog.append(spannable);
    /* Auto-scroll to bottom — layout may be null before the first
     * measure pass or after onPause() clears the text. */
    android.text.Layout layout = chatLog.getLayout();
    if (layout != null) {
      int scrollAmount = layout.getLineTop(chatLog.getLineCount()) - chatLog.getHeight();
      if (scrollAmount > 0) chatLog.scrollTo(0, scrollAmount);
    }
  }

  /* ---- Local IPs ------------------------------------------------------ */

  private String getLocalIps() {
    int port = getIntent().getIntExtra("port", 7777);
    List<String> ipv4 = new ArrayList<>();
    List<String> ipv6 = new ArrayList<>();
    try {
      for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
        if (!ni.isUp() || ni.isLoopback()) continue;
        for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
          if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()) continue;
          String ip = addr.getHostAddress();
          if (addr instanceof Inet6Address) {
            ip = ip.replaceAll("%.*", "");
            ipv6.add(ip);
          } else {
            ipv4.add(ip);
          }
        }
      }
    } catch (Exception ignored) {
    }
    /* Prefer IPv4 -- shorter, easier to type */
    List<String> ips = ipv4.isEmpty() ? ipv6 : ipv4;
    StringBuilder sb = new StringBuilder();
    for (String ip : ips) {
      if (sb.length() > 0) sb.append("\n");
      sb.append("simplecipher connect ").append(ip).append(" ").append(port);
    }
    return sb.toString();
  }

  /* ---- Lifecycle ------------------------------------------------------- */

  @Override
  protected void onResume() {
    super.onResume();
    paused = false;
  }

  @Override
  protected void onPause() {
    paused = true;
    /* Best-effort wipe of sensitive text from UI widgets.
     *
     * LIMITATION: Java Strings are immutable and garbage-collected.
     * setText("") replaces the widget reference but the old String
     * content remains in the Java heap until the GC reclaims it, and
     * even then the memory is not zeroed.  This means the Android
     * build cannot make the same memory-hygiene guarantee as the
     * desktop C code (which uses crypto_wipe on every buffer).
     *
     * What we CAN do: clear widgets promptly (reduces the window),
     * block new plaintext from arriving while paused (the paused
     * flag above), and rely on FLAG_SECURE to prevent screenshots.
     * For stronger guarantees, use the desktop CLI/TUI build. */
    if (inAppKeyboard != null) {
      inAppKeyboard.setVisibility(android.view.View.GONE);
      inAppKeyboard.setTarget(null);
    }
    if (statusText != null) statusText.setText("");
    if (sasInput != null) sasInput.setText("");
    if (sasCodeText != null) sasCodeText.setText("");
    if (chatLog != null) chatLog.setText("");
    if (chatInput != null) chatInput.setText("");
    pendingSas = null;
    pendingSendMsg = null; /* wipe unsent plaintext from activity field */
    super.onPause();
  }

  @Override
  protected void onStop() {
    /* Treat backgrounding as session end.  The moment this activity is
     * no longer visible, disconnect and wipe all native session state.
     * This is more aggressive than waiting for onDestroy: it ensures
     * that switching apps, pressing home, or locking the screen kills
     * the session immediately.  Users must reconnect when they return.
     *
     * nativeStop() is out-of-band: it directly closes/shuts down the
     * pipe, socket, and listen socket, unblocking the session thread
     * for most phases.  The SOCKS5 handshake path uses deadline-aware
     * I/O and may take up to 30 seconds to abort if the proxy stalls.
     *
     * Rationale: a backgrounded app with live crypto state in memory
     * is a target for memory-dumping attacks.  Ending the session on
     * stop reduces the exposure window to only the time the user is
     * actively looking at the screen. */
    sessionLive = false;
    pendingSendMsg = null;
    nativeStop();
    if (statusText != null) statusText.setText("");
    if (sasInput != null) sasInput.setText("");
    if (sasCodeText != null) sasCodeText.setText("");
    if (chatLog != null) chatLog.setText("");
    if (chatInput != null) chatInput.setText("");
    super.onStop();
  }

  @Override
  public void onBackPressed() {
    /* Clean disconnect when the user presses the back button. */
    nativeStop();
    super.onBackPressed();
  }

  @Override
  protected void onDestroy() {
    /* Belt-and-suspenders: call nativeStop again in case onStop didn't
     * run (e.g. the system killed the process). nativeStop is idempotent:
     * closing an already-closed fd or shutting down an already-shut-down
     * socket is harmless. */
    nativeStop();
    super.onDestroy();
  }

  /* ---- System keyboard suppression ------------------------------------ */

  /**
   * Forcibly dismiss the system IME for the given view.
   *
   * <p>We call this whenever an EditText gains focus. Combined with setShowSoftInputOnFocus(false)
   * and SOFT_INPUT_STATE_ALWAYS_HIDDEN on the window, this ensures the system keyboard never
   * appears. The triple-layer approach is necessary because no single method works reliably across
   * all Android versions and OEM ROMs.
   */
  private void hideSystemKeyboard(View view) {
    InputMethodManager imm = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
    if (imm != null) {
      imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
    }
  }

  /* ---- Utility -------------------------------------------------------- */

  private int dp(int dp) {
    return (int) (dp * getResources().getDisplayMetrics().density + 0.5f);
  }
}
