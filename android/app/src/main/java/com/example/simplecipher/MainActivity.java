package com.example.simplecipher;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MainActivity extends Activity {

  static {
    System.loadLibrary("simplecipher");
  }

  private native String nativeGenerateKey();

  private native void nativeWipePreKey();

  private native void nativeSetPeerFingerprint(String fingerprint);

  private native void nativeClearPeerFingerprint();

  private RadioGroup modeGroup;
  private TextView connectLabel;
  private EditText hostInput;
  private EditText portInput;
  private LinearLayout advancedSection;
  private LinearLayout advancedContent;
  private EditText socks5Input;
  private boolean advancedExpanded = false;
  private LinearLayout localIpsContainer;
  private LinearLayout fpContent;
  private ImageView fpQrImage;
  private TextView fpSelfText;
  private Button fpScanBtn;
  private EditText fpManualInput;
  private TextView fpPeerStatus;
  private CheckBox fpTrustCheckbox;
  private boolean fpExpanded = false;
  private String selfFingerprint = null;
  private String peerFingerprint = null;
  private final Handler clipboardHandler = new Handler(Looper.getMainLooper());
  private final QrHelper qr = new QrHelperImpl();
  private SimpleKeyboard inAppKeyboard;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    getWindow()
        .setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
    if (android.os.Build.VERSION.SDK_INT >= 31) getWindow().setHideOverlayWindows(true);
    setContentView(R.layout.activity_main);

    modeGroup = findViewById(R.id.modeGroup);
    connectLabel = findViewById(R.id.connectLabel);
    hostInput = findViewById(R.id.hostInput);
    portInput = findViewById(R.id.portInput);
    advancedSection = findViewById(R.id.advancedSection);
    advancedContent = findViewById(R.id.advancedContent);
    socks5Input = findViewById(R.id.socks5Input);

    /* Collapsible "Advanced" toggle — hidden by default, shows SOCKS5 proxy */
    TextView advancedToggle = findViewById(R.id.advancedToggle);
    advancedToggle.setOnClickListener(
        v -> {
          advancedExpanded = !advancedExpanded;
          advancedContent.setVisibility(advancedExpanded ? View.VISIBLE : View.GONE);
          advancedToggle.setText(
              advancedExpanded ? "\u25BC Advanced" : getString(R.string.advanced_section_title));
        });
    localIpsContainer = findViewById(R.id.localIpsContainer);
    Button goButton = findViewById(R.id.goButton);

    /* Custom in-app keyboard — same as ChatActivity.  Prevents the
     * system keyboard from receiving host, port, or fingerprint data.
     * Without this, a malicious third-party keyboard could log the
     * connect target (revealing who you talked to) or the peer's
     * fingerprint. */
    inAppKeyboard = findViewById(R.id.mainKeyboard);

    /* Suppress the system soft keyboard at the window level */
    getWindow()
        .setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

    /* Suppress system keyboard on all EditTexts and show our keyboard instead */
    hostInput.setShowSoftInputOnFocus(false);
    portInput.setShowSoftInputOnFocus(false);
    socks5Input.setShowSoftInputOnFocus(false);

    hostInput.setOnFocusChangeListener(
        (v, hasFocus) -> {
          if (hasFocus) {
            hideSystemKeyboard(hostInput);
            inAppKeyboard.setMode(SimpleKeyboard.MODE_TEXT);
            inAppKeyboard.setTarget(hostInput);
            inAppKeyboard.setVisibility(View.VISIBLE);
          }
        });

    portInput.setOnFocusChangeListener(
        (v, hasFocus) -> {
          if (hasFocus) {
            hideSystemKeyboard(portInput);
            inAppKeyboard.setMode(SimpleKeyboard.MODE_NUMERIC);
            inAppKeyboard.setTarget(portInput);
            inAppKeyboard.setVisibility(View.VISIBLE);
          }
        });

    socks5Input.setOnFocusChangeListener(
        (v, hasFocus) -> {
          if (hasFocus) {
            hideSystemKeyboard(socks5Input);
            inAppKeyboard.setMode(SimpleKeyboard.MODE_TEXT);
            inAppKeyboard.setTarget(socks5Input);
            inAppKeyboard.setVisibility(View.VISIBLE);
          }
        });

    /* Suppress keyboard learning on all inputs — peer IPs, ports, and
     * proxy addresses are sensitive metadata that should not enter IME dictionaries. */
    int noLearn = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING;
    hostInput.setImeOptions(hostInput.getImeOptions() | noLearn);
    portInput.setImeOptions(portInput.getImeOptions() | noLearn);
    socks5Input.setImeOptions(socks5Input.getImeOptions() | noLearn);

    showLocalIps();

    /* Fingerprint verification panel */
    TextView fpToggle = findViewById(R.id.fpToggle);
    fpContent = findViewById(R.id.fpContent);
    fpQrImage = findViewById(R.id.fpQrImage);
    fpSelfText = findViewById(R.id.fpSelfText);
    fpScanBtn = findViewById(R.id.fpScanBtn);
    fpManualInput = findViewById(R.id.fpManualInput);
    fpPeerStatus = findViewById(R.id.fpPeerStatus);
    fpTrustCheckbox = findViewById(R.id.fpTrustCheckbox);

    int noLearnFp = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING;
    fpManualInput.setImeOptions(fpManualInput.getImeOptions() | noLearnFp);
    fpManualInput.setShowSoftInputOnFocus(false);
    fpManualInput.setOnFocusChangeListener(
        (v, hasFocus) -> {
          if (hasFocus) {
            hideSystemKeyboard(fpManualInput);
            inAppKeyboard.setMode(SimpleKeyboard.MODE_HEX);
            inAppKeyboard.setTarget(fpManualInput);
            inAppKeyboard.setVisibility(View.VISIBLE);
          }
        });

    /* Expand/collapse: on first expand, generate an ephemeral keypair
     * and display the self fingerprint.  The user shares this with their
     * peer (QR code, paper, or read aloud) so the peer can verify our
     * identity after the handshake completes. */
    fpToggle.setOnClickListener(
        v -> {
          fpExpanded = !fpExpanded;
          fpContent.setVisibility(fpExpanded ? View.VISIBLE : View.GONE);
          if (fpExpanded && selfFingerprint == null) {
            selfFingerprint = nativeGenerateKey();
            if (selfFingerprint == null) {
              Toast.makeText(this, "Key generation failed", Toast.LENGTH_SHORT).show();
              fpExpanded = false;
              fpContent.setVisibility(View.GONE);
              return;
            }
            fpSelfText.setText(selfFingerprint);
            if (qr.hasScanner()) {
              fpQrImage.setImageBitmap(qr.generateBitmap(selfFingerprint, 512));
            }
          }
        });

    if (qr.hasScanner()) {
      fpScanBtn.setOnClickListener(
          v -> {
            if (checkSelfPermission(android.Manifest.permission.CAMERA)
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
              requestPermissions(new String[] {android.Manifest.permission.CAMERA}, 100);
            } else {
              qr.launchScanner(this);
            }
          });
    } else {
      /* Minimal flavor: hide scan button and QR image */
      fpScanBtn.setVisibility(View.GONE);
      fpQrImage.setVisibility(View.GONE);
    }

    /* Manual text entry: when the user types all 16 hex digits of the
     * peer's fingerprint, store it in native memory for verification
     * after the handshake.  This is the fallback for devices without
     * cameras or when the minimal (no-QR) flavor is installed. */
    fpManualInput.addTextChangedListener(
        new android.text.TextWatcher() {
          public void beforeTextChanged(CharSequence s, int a, int b, int c) {}

          public void onTextChanged(CharSequence s, int a, int b, int c) {}

          public void afterTextChanged(android.text.Editable s) {
            String text = s.toString().trim();
            String stripped = text.replace("-", "");
            if (stripped.length() == 16 && stripped.matches("[0-9A-Fa-f]+")) {
              setPeerFingerprint(text);
            } else if (peerFingerprint != null) {
              /* Input no longer valid — clear the stored fingerprint
               * so a stale value doesn't get used for verification. */
              clearPeerFingerprint();
            }
          }
        });

    /* Refresh IP commands when port changes so the displayed
     * connect commands always show the correct port number. */
    portInput.addTextChangedListener(
        new android.text.TextWatcher() {
          public void beforeTextChanged(CharSequence s, int a, int b, int c) {}

          public void onTextChanged(CharSequence s, int a, int b, int c) {}

          public void afterTextChanged(android.text.Editable s) {
            showLocalIps();
          }
        });

    modeGroup.setOnCheckedChangeListener(
        (group, checkedId) -> {
          boolean isConnect = checkedId == R.id.radioConnect;
          connectLabel.setVisibility(isConnect ? View.VISIBLE : View.GONE);
          hostInput.setVisibility(isConnect ? View.VISIBLE : View.GONE);
          advancedSection.setVisibility(isConnect ? View.VISIBLE : View.GONE);
          localIpsContainer.setVisibility(isConnect ? View.GONE : View.VISIBLE);
        });

    /* Enter key on port field triggers Go */
    goButton.setOnClickListener(
        v -> {
          boolean isConnect = modeGroup.getCheckedRadioButtonId() == R.id.radioConnect;

          String portStr = portInput.getText().toString().trim();
          if (portStr.isEmpty()) portStr = "7777";
          int port;
          try {
            port = Integer.parseInt(portStr);
            if (port < 1 || port > 65535) throw new NumberFormatException();
          } catch (NumberFormatException e) {
            Toast.makeText(this, "Invalid port", Toast.LENGTH_SHORT).show();
            return;
          }

          String host = "";
          if (isConnect) {
            host = hostInput.getText().toString().trim();
            if (host.isEmpty()) {
              Toast.makeText(this, "Host required", Toast.LENGTH_SHORT).show();
              return;
            }
          }

          String socks5 = socks5Input.getText().toString().trim();

          /* Direct connect (no proxy): require numeric IP address.
           * Hostnames would cause blocking DNS in the native thread,
           * which nativeStop() cannot interrupt. With SOCKS5, the
           * proxy resolves DNS so hostnames (.onion etc.) are fine. */
          if (isConnect && socks5.isEmpty() && !isNumericAddress(host)) {
            Toast.makeText(
                    this,
                    "Direct connect requires an IP address (not a hostname).\n"
                        + "For .onion or hostnames, use a SOCKS5 proxy.",
                    Toast.LENGTH_LONG)
                .show();
            return;
          }
          if (!socks5.isEmpty()) {
            /* Validate host:port format and enforce loopback-only.
             * The SOCKS5 connect uses blocking I/O (not interruptible
             * by nativeStop), so we restrict to localhost where TCP
             * connect completes instantly. Remote proxies could hang
             * the session thread indefinitely. */
            int colon = socks5.lastIndexOf(':');
            if (colon <= 0 || colon == socks5.length() - 1) {
              Toast.makeText(
                      this, "Proxy must be host:port (e.g. 127.0.0.1:9050)", Toast.LENGTH_SHORT)
                  .show();
              return;
            }
            String proxyHost = socks5.substring(0, colon);
            if (!proxyHost.equals("127.0.0.1")
                && !proxyHost.equals("localhost")
                && !proxyHost.equals("::1")) {
              Toast.makeText(
                      this,
                      "Proxy must be on localhost (127.0.0.1, localhost, or ::1)",
                      Toast.LENGTH_LONG)
                  .show();
              return;
            }
          }

          Intent intent = new Intent(this, ChatActivity.class);
          intent.putExtra("mode", isConnect ? "connect" : "listen");
          intent.putExtra("host", host);
          intent.putExtra("port", port);
          if (!socks5.isEmpty()) intent.putExtra("socks5_proxy", socks5);
          if (fpTrustCheckbox.isChecked()) intent.putExtra("trust_fingerprint", true);
          startActivity(intent);
        });
  }

  @Override
  protected void onStop() {
    if (inAppKeyboard != null) inAppKeyboard.setVisibility(View.GONE);
    /* Clear any pending clipboard auto-clear callbacks and clear clipboard now */
    clipboardHandler.removeCallbacksAndMessages(null);
    ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
    if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("", ""));
    /* Wipe pre-generated key when app is backgrounded.
     * LIFECYCLE INVARIANT: when MainActivity starts ChatActivity,
     * Android guarantees: A.onPause -> B.onCreate -> ... -> A.onStop.
     * So nativeStart() (in ChatActivity.onCreate) copies+wipes globals
     * before this runs. This is the cleanup path for backgrounding
     * without connecting. */
    nativeWipePreKey();
    selfFingerprint = null;
    peerFingerprint = null;
    if (hostInput != null) hostInput.setText("");
    if (portInput != null) portInput.setText("");
    if (localIpsContainer != null) localIpsContainer.removeAllViews();
    if (fpQrImage != null) fpQrImage.setImageBitmap(null);
    if (fpSelfText != null) fpSelfText.setText("");
    if (fpManualInput != null) fpManualInput.setText("");
    if (socks5Input != null) socks5Input.setText("");
    advancedExpanded = false;
    if (advancedContent != null) advancedContent.setVisibility(View.GONE);
    if (fpPeerStatus != null) fpPeerStatus.setText(R.string.fp_peer_none);
    fpExpanded = false;
    if (fpContent != null) fpContent.setVisibility(View.GONE);
    super.onStop();
  }

  @Override
  protected void onDestroy() {
    nativeWipePreKey();
    super.onDestroy();
  }

  private void hideSystemKeyboard(View view) {
    android.view.inputmethod.InputMethodManager imm =
        (android.view.inputmethod.InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
    if (imm != null) {
      imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
    }
  }

  private void showLocalIps() {
    localIpsContainer.removeAllViews();
    List<String> ips = getLocalIps();

    if (ips.isEmpty()) {
      TextView noNet = new TextView(this);
      noNet.setText("No network interfaces found");
      noNet.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
      noNet.setTextColor(0xFF999999);
      noNet.setGravity(Gravity.CENTER);
      localIpsContainer.addView(noNet);
      return;
    }

    /* Label */
    TextView label = new TextView(this);
    label.setText("Tell your peer to run:");
    label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
    label.setTextColor(0xFF666666);
    label.setPadding(dp(4), 0, 0, dp(8));
    localIpsContainer.addView(label);

    String portStr = portInput.getText().toString().trim();
    if (portStr.isEmpty()) portStr = "7777";

    for (int i = 0; i < ips.size(); i++) {
      String ip = ips.get(i);
      String cmd = "simplecipher connect " + ip + " " + portStr;

      LinearLayout row = new LinearLayout(this);
      row.setOrientation(LinearLayout.HORIZONTAL);
      row.setGravity(Gravity.CENTER_VERTICAL);
      row.setPadding(dp(16), dp(12), dp(12), dp(12));
      row.setBackgroundResource(R.drawable.bg_ip_row);

      /* Command text */
      TextView ipText = new TextView(this);
      ipText.setText(cmd);
      ipText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
      ipText.setTextColor(0xFFF0F0F0);
      ipText.setTypeface(android.graphics.Typeface.MONOSPACE);
      ipText.setLetterSpacing(0.02f);
      ipText.setSingleLine(true);
      ipText.setEllipsize(android.text.TextUtils.TruncateAt.END);
      LinearLayout.LayoutParams textParams =
          new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
      ipText.setLayoutParams(textParams);
      row.addView(ipText);

      /* Copy button — filterTouchesWhenObscured prevents overlay tapjacking */
      TextView copyBtn = new TextView(this);
      copyBtn.setText("COPY");
      copyBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
      copyBtn.setTextColor(0xFF4DD0B0);
      copyBtn.setTypeface(null, android.graphics.Typeface.BOLD);
      copyBtn.setLetterSpacing(0.05f);
      copyBtn.setPadding(dp(12), dp(6), dp(4), dp(6));
      copyBtn.setFilterTouchesWhenObscured(true);
      copyBtn.setOnClickListener(
          v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText("connect command", cmd);
            /* Best-effort clipboard protection.  EXTRA_IS_SENSITIVE (API 33+)
             * asks the OS to hide the preview.  On API 28-29, background apps
             * can still read the clipboard — the warning below tells the user.
             * Clipboard copy is a convenience, not a secure channel. */
            if (android.os.Build.VERSION.SDK_INT >= 33) {
              android.os.PersistableBundle extras = new android.os.PersistableBundle();
              extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
              clip.getDescription().setExtras(extras);
            }
            cm.setPrimaryClip(clip);
            Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
            if (android.os.Build.VERSION.SDK_INT < 30) {
              Toast.makeText(
                      this,
                      "Note: older Android versions may expose clipboard to other apps",
                      Toast.LENGTH_LONG)
                  .show();
            }
            /* Auto-clear clipboard after 30 seconds.
             * Uses a field-level Handler so the callback survives
             * view detachment (localIpsContainer.removeAllViews). */
            clipboardHandler.postDelayed(
                () -> {
                  ClipboardManager cmClear = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                  if (cmClear != null) cmClear.setPrimaryClip(ClipData.newPlainText("", ""));
                },
                30000);
          });
      row.addView(copyBtn);

      LinearLayout.LayoutParams rowParams =
          new LinearLayout.LayoutParams(
              LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
      if (i > 0) rowParams.topMargin = dp(8);
      row.setLayoutParams(rowParams);

      localIpsContainer.addView(row);
    }
  }

  private int dp(int value) {
    return (int)
        TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics());
  }

  private List<String> getLocalIps() {
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
    /* Prefer IPv4 -- shorter, easier to read aloud and type.
     * Only show IPv6 if no IPv4 addresses are available. */
    return ipv4.isEmpty() ? ipv6 : ipv4;
  }

  /* ---- QR result handling (delegates to flavor-specific QrHelper) -------- */

  @Override
  protected void onActivityResult(int requestCode, int resultCode, android.content.Intent data) {
    String scanned = qr.parseScanResult(requestCode, resultCode, data);
    if (scanned != null) {
      setPeerFingerprint(scanned);
    } else {
      super.onActivityResult(requestCode, resultCode, data);
    }
  }

  @Override
  public void onRequestPermissionsResult(
      int requestCode, String[] permissions, int[] grantResults) {
    if (qr.hasScanner()
        && requestCode == 100
        && grantResults.length > 0
        && grantResults[0] == android.content.pm.PackageManager.PERMISSION_GRANTED) {
      qr.launchScanner(this);
    } else if (requestCode == 100) {
      Toast.makeText(this, R.string.fp_camera_denied, Toast.LENGTH_SHORT).show();
    }
  }

  private void clearPeerFingerprint() {
    peerFingerprint = null;
    nativeClearPeerFingerprint();
    fpPeerStatus.setText(R.string.fp_peer_none);
    fpPeerStatus.setTextColor(0xFFAAAAAA);
    fpTrustCheckbox.setChecked(false);
    fpTrustCheckbox.setVisibility(View.GONE);
  }

  private void setPeerFingerprint(String fp) {
    String normalized = fp.trim().toUpperCase(java.util.Locale.ROOT);
    String stripped = normalized.replace("-", "");
    if (stripped.length() != 16 || !stripped.matches("[0-9A-F]+")) {
      /* Clear any previously valid fingerprint — don't leave stale
       * state armed after an invalid scan or edit. */
      if (peerFingerprint != null) clearPeerFingerprint();
      Toast.makeText(this, "Invalid fingerprint format", Toast.LENGTH_SHORT).show();
      return;
    }
    peerFingerprint =
        stripped.substring(0, 4)
            + "-"
            + stripped.substring(4, 8)
            + "-"
            + stripped.substring(8, 12)
            + "-"
            + stripped.substring(12, 16);
    nativeSetPeerFingerprint(peerFingerprint);
    fpPeerStatus.setText(getString(R.string.fp_peer_set, peerFingerprint));
    fpPeerStatus.setTextColor(0xFF4DD0B0);
    fpManualInput.setText(peerFingerprint);
    fpTrustCheckbox.setVisibility(View.VISIBLE);
  }

  /** Check if a string is a numeric IP address (IPv4 or IPv6, no DNS). */
  private static boolean isNumericAddress(String host) {
    /* InetAddress.getByName would do DNS — avoid it.
     * Simple pattern: IPv4 is digits+dots, IPv6 contains colons. */
    if (host.contains(":")) return true; /* IPv6 */
    return host.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
  }
}
