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
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.view.WindowManager;
import android.widget.Toast;

import android.widget.ImageView;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MainActivity extends Activity {

    static { System.loadLibrary("simplecipher"); }

    private native String nativeGenerateKey();
    private native void   nativeWipePreKey();
    private native void   nativeSetPeerFingerprint(String fingerprint);

    private RadioGroup    modeGroup;
    private TextView      connectLabel;
    private EditText      hostInput;
    private EditText      portInput;
    private LinearLayout  localIpsContainer;
    private LinearLayout  fpContent;
    private ImageView     fpQrImage;
    private TextView      fpSelfText;
    private Button        fpScanBtn;
    private EditText      fpManualInput;
    private TextView      fpPeerStatus;
    private boolean       fpExpanded = false;
    private String        selfFingerprint = null;
    private String        peerFingerprint = null;
    private final QrHelper qr = new QrHelperImpl();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                             WindowManager.LayoutParams.FLAG_SECURE);
        if (android.os.Build.VERSION.SDK_INT >= 31)
            getWindow().setHideOverlayWindows(true);
        setContentView(R.layout.activity_main);

        modeGroup        = findViewById(R.id.modeGroup);
        connectLabel     = findViewById(R.id.connectLabel);
        hostInput        = findViewById(R.id.hostInput);
        portInput        = findViewById(R.id.portInput);
        localIpsContainer = findViewById(R.id.localIpsContainer);
        Button goButton  = findViewById(R.id.goButton);

        /* Suppress keyboard learning on all inputs — peer IPs and ports
         * are sensitive metadata that should not enter IME dictionaries. */
        int noLearn = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING;
        hostInput.setImeOptions(hostInput.getImeOptions() | noLearn);
        portInput.setImeOptions(portInput.getImeOptions() | noLearn);

        showLocalIps();

        /* Fingerprint verification panel */
        TextView fpToggle   = findViewById(R.id.fpToggle);
        fpContent     = findViewById(R.id.fpContent);
        fpQrImage     = findViewById(R.id.fpQrImage);
        fpSelfText    = findViewById(R.id.fpSelfText);
        fpScanBtn     = findViewById(R.id.fpScanBtn);
        fpManualInput = findViewById(R.id.fpManualInput);
        fpPeerStatus  = findViewById(R.id.fpPeerStatus);

        int noLearnFp = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING;
        fpManualInput.setImeOptions(fpManualInput.getImeOptions() | noLearnFp);

        fpToggle.setOnClickListener(v -> {
            fpExpanded = !fpExpanded;
            fpContent.setVisibility(fpExpanded ? View.VISIBLE : View.GONE);
            if (fpExpanded && selfFingerprint == null) {
                selfFingerprint = nativeGenerateKey();
                fpSelfText.setText(selfFingerprint);
                if (qr.hasScanner()) {
                    fpQrImage.setImageBitmap(qr.generateBitmap(selfFingerprint, 512));
                }
            }
        });

        if (qr.hasScanner()) {
            fpScanBtn.setOnClickListener(v -> {
                if (checkSelfPermission(android.Manifest.permission.CAMERA)
                        != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                    requestPermissions(new String[]{android.Manifest.permission.CAMERA}, 100);
                } else {
                    qr.launchScanner(this);
                }
            });
        } else {
            /* Minimal flavor: hide scan button and QR image */
            fpScanBtn.setVisibility(View.GONE);
            fpQrImage.setVisibility(View.GONE);
        }

        fpManualInput.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            public void onTextChanged(CharSequence s, int a, int b, int c) {}
            public void afterTextChanged(android.text.Editable s) {
                String text = s.toString().trim();
                if (text.replace("-", "").length() == 16) {
                    setPeerFingerprint(text);
                }
            }
        });

        /* Refresh IP commands when port changes so the displayed
         * connect commands always show the correct port number. */
        portInput.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            public void onTextChanged(CharSequence s, int a, int b, int c) {}
            public void afterTextChanged(android.text.Editable s) { showLocalIps(); }
        });

        modeGroup.setOnCheckedChangeListener((group, checkedId) -> {
            boolean isConnect = checkedId == R.id.radioConnect;
            connectLabel.setVisibility(isConnect ? View.VISIBLE : View.GONE);
            hostInput.setVisibility(isConnect ? View.VISIBLE : View.GONE);
            localIpsContainer.setVisibility(isConnect ? View.GONE : View.VISIBLE);
        });

        /* Enter key on port field triggers Go */
        goButton.setOnClickListener(v -> {
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

            Intent intent = new Intent(this, ChatActivity.class);
            intent.putExtra("mode", isConnect ? "connect" : "listen");
            intent.putExtra("host", host);
            intent.putExtra("port", port);
            startActivity(intent);
        });
    }

    @Override
    protected void onStop() {
        /* Wipe pre-generated key when app is backgrounded.
         * LIFECYCLE INVARIANT: when MainActivity starts ChatActivity,
         * Android guarantees: A.onPause -> B.onCreate -> ... -> A.onStop.
         * So nativeStart() (in ChatActivity.onCreate) copies+wipes globals
         * before this runs. This is the cleanup path for backgrounding
         * without connecting. */
        nativeWipePreKey();
        selfFingerprint = null;
        peerFingerprint = null;
        if (fpQrImage != null) fpQrImage.setImageBitmap(null);
        if (fpSelfText != null) fpSelfText.setText("");
        if (fpManualInput != null) fpManualInput.setText("");
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
            LinearLayout.LayoutParams textParams = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
            ipText.setLayoutParams(textParams);
            row.addView(ipText);

            /* Copy button */
            TextView copyBtn = new TextView(this);
            copyBtn.setText("COPY");
            copyBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            copyBtn.setTextColor(0xFF4DD0B0);
            copyBtn.setTypeface(null, android.graphics.Typeface.BOLD);
            copyBtn.setLetterSpacing(0.05f);
            copyBtn.setPadding(dp(12), dp(6), dp(4), dp(6));
            copyBtn.setOnClickListener(v -> {
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText("connect command", cmd);
                /* Mark as sensitive so the OS hides the preview in clipboard
                 * UI and other apps cannot snoop it via ClipboardManager. */
                if (android.os.Build.VERSION.SDK_INT >= 33) {
                    android.os.PersistableBundle extras = new android.os.PersistableBundle();
                    extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
                    clip.getDescription().setExtras(extras);
                }
                cm.setPrimaryClip(clip);
                Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
                /* Auto-clear clipboard after 30 seconds */
                new Handler(Looper.getMainLooper()).postDelayed(() -> {
                    cm.setPrimaryClip(ClipData.newPlainText("", ""));
                }, 30000);
            });
            row.addView(copyBtn);

            LinearLayout.LayoutParams rowParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            if (i > 0) rowParams.topMargin = dp(8);
            row.setLayoutParams(rowParams);

            localIpsContainer.addView(row);
        }
    }

    private int dp(int value) {
        return (int) TypedValue.applyDimension(
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
        } catch (Exception ignored) {}
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
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (qr.hasScanner() && requestCode == 100 && grantResults.length > 0
                && grantResults[0] == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            qr.launchScanner(this);
        } else if (requestCode == 100) {
            Toast.makeText(this, R.string.fp_camera_denied, Toast.LENGTH_SHORT).show();
        }
    }

    private void setPeerFingerprint(String fp) {
        String normalized = fp.trim().toUpperCase(java.util.Locale.ROOT);
        String stripped = normalized.replace("-", "");
        if (stripped.length() != 16 || !stripped.matches("[0-9A-F]+")) {
            Toast.makeText(this, "Invalid fingerprint format", Toast.LENGTH_SHORT).show();
            return;
        }
        peerFingerprint = stripped.substring(0,4) + "-" + stripped.substring(4,8)
                + "-" + stripped.substring(8,12) + "-" + stripped.substring(12,16);
        nativeSetPeerFingerprint(peerFingerprint);
        fpPeerStatus.setText(getString(R.string.fp_peer_set, peerFingerprint));
        fpPeerStatus.setTextColor(0xFF4DD0B0);
        fpManualInput.setText(peerFingerprint);
    }
}
