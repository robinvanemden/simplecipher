package com.example.simplecipher;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.view.WindowManager;
import android.widget.Toast;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class ChatActivity extends Activity {

    static { System.loadLibrary("simplecipher"); }

    /* JNI methods */
    private native int     nativeInit();
    private native int     nativeConnect(String host, int port);
    private native int     nativeListen(int port);
    private native String  nativeHandshake();
    private native int     nativeConfirmSas();
    private native int     nativeSend(String msg);
    private native String  nativeReceive();
    private native void    nativeDisconnect();

    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    /* UI elements */
    private TextView    statusText;
    private LinearLayout sasLayout;
    private TextView    sasCodeText;
    private EditText    sasInput;
    private Button      sasConfirmBtn;
    private LinearLayout chatLayout;
    private TextView    chatLog;
    private EditText    chatInput;
    private Button      sendBtn;

    private volatile boolean running = true;
    private volatile boolean paused  = false;
    private Thread networkThread;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                             WindowManager.LayoutParams.FLAG_SECURE);
        /* HIDE_OVERLAY_WINDOWS prevents other apps from drawing on top of
         * this activity (tapjacking, screen recording overlays). */
        if (android.os.Build.VERSION.SDK_INT >= 31)
            getWindow().setHideOverlayWindows(true);
        setContentView(R.layout.activity_chat);

        statusText    = findViewById(R.id.statusText);
        sasLayout     = findViewById(R.id.sasLayout);
        sasCodeText   = findViewById(R.id.sasCodeText);
        sasInput      = findViewById(R.id.sasInput);
        sasConfirmBtn = findViewById(R.id.sasConfirmBtn);
        chatLayout    = findViewById(R.id.chatLayout);
        chatLog       = findViewById(R.id.chatLog);
        chatInput     = findViewById(R.id.chatInput);
        sendBtn       = findViewById(R.id.sendBtn);

        /* Tell the soft keyboard not to learn from anything the user types
         * in this activity.  IMEs may ignore this, but it is the strongest
         * signal Android provides short of a custom in-app keyboard. */
        int noLearn = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING;
        sasInput.setImeOptions(sasInput.getImeOptions() | noLearn);
        chatInput.setImeOptions(chatInput.getImeOptions() | noLearn);

        chatLog.setMovementMethod(new ScrollingMovementMethod());

        String mode = getIntent().getStringExtra("mode");
        String host = getIntent().getStringExtra("host");
        int port    = getIntent().getIntExtra("port", 7777);

        boolean isConnect = "connect".equals(mode);

        if (isConnect) {
            statusText.setText("Connecting to " + host + ":" + port + " ...");
        } else {
            String ips = getLocalIps();
            if (ips.isEmpty()) {
                statusText.setText("Listening on port " + port + "\nNo network interfaces found");
            } else {
                statusText.setText("Listening on port " + port
                    + "\n\nTell your peer to run:\n" + ips);
            }
        }

        nativeInit();

        /* Connection + handshake on background thread */
        networkThread = new Thread(() -> {
            int rc;
            if (isConnect) {
                rc = nativeConnect(host, port);
            } else {
                rc = nativeListen(port);
            }

            if (rc != 0) {
                uiHandler.post(() -> {
                    statusText.setText("Connection failed");
                    Toast.makeText(this, "Connection failed", Toast.LENGTH_LONG).show();
                });
                return;
            }

            uiHandler.post(() -> statusText.setText("Connected. Performing handshake..."));

            String sas = nativeHandshake();
            if (sas == null || sas.isEmpty()) {
                uiHandler.post(() -> {
                    statusText.setText("Handshake failed");
                    Toast.makeText(this, "Handshake failed", Toast.LENGTH_LONG).show();
                });
                return;
            }

            /* Show SAS verification UI */
            uiHandler.post(() -> {
                statusText.setText("Verify safety code with your peer");
                sasCodeText.setText(sas);
                sasLayout.setVisibility(View.VISIBLE);

                /* Enter key on SAS input triggers verify */
                sasInput.setOnEditorActionListener((v2, a, e) -> {
                    sasConfirmBtn.performClick();
                    return true;
                });

                sasConfirmBtn.setOnClickListener(v -> {
                    /* Normalize: strip dashes and uppercase.  Accepts "A3F2-91BC",
                     * "A3F291BC", "a3f291bc" etc.  Full comparison ensures the user
                     * verifies all 32 bits of the SAS, not just the first 16. */
                    String typed = sasInput.getText().toString().trim()
                            .replace("-", "").toUpperCase(Locale.ROOT);
                    String expected = sas.replace("-", "").toUpperCase(Locale.ROOT);
                    if (!typed.equals(expected)) {
                        Toast.makeText(this, "Code mismatch - aborting",
                                       Toast.LENGTH_LONG).show();
                        disconnect();
                        finish();
                        return;
                    }

                    nativeConfirmSas();
                    sasInput.setText("");
                    sasCodeText.setText("");
                    sasLayout.setVisibility(View.GONE);
                    chatLayout.setVisibility(View.VISIBLE);
                    statusText.setText("\uD83D\uDD12 Secure session active");
                    statusText.setTextColor(0xFF4DD0B0);

                    /* Start receive loop */
                    startReceiveLoop();

                    /* Wire send button + Enter key */
                    sendBtn.setOnClickListener(sv -> sendMessage());
                    chatInput.setOnEditorActionListener((tv, actionId, event) -> {
                        sendMessage();
                        return true;
                    });
                });
            });
        });
        networkThread.start();
    }

    private void sendMessage() {
        String msg = chatInput.getText().toString().trim();
        if (msg.isEmpty()) return;
        chatInput.setText("");

        new Thread(() -> {
            int rc = nativeSend(msg);
            uiHandler.post(() -> {
                if (rc == 0) {
                    appendChat("me", msg);
                } else {
                    appendChat("system", "[send failed]");
                }
            });
        }).start();
    }

    private void startReceiveLoop() {
        new Thread(() -> {
            while (running) {
                String msg = nativeReceive();
                if (msg == null) {
                    uiHandler.post(() -> {
                        appendChat("system", "[peer disconnected]");
                        sendBtn.setEnabled(false);
                    });
                    break;
                }
                uiHandler.post(() -> appendChat("peer", msg));
            }
        }).start();
    }

    private void appendChat(String who, String msg) {
        /* Do not write plaintext to the UI while paused.  onPause() wipes
         * the widgets; allowing the receive thread to repopulate chatLog
         * after the wipe would leak plaintext into the Java heap while
         * the app is backgrounded. */
        if (paused) return;
        String ts = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
        String line = "[" + ts + "] " + who + ": " + msg + "\n";
        chatLog.append(line);
        /* Auto-scroll to bottom */
        int scrollAmount = chatLog.getLayout().getLineTop(chatLog.getLineCount())
                           - chatLog.getHeight();
        if (scrollAmount > 0) chatLog.scrollTo(0, scrollAmount);
    }

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
        } catch (Exception ignored) {}
        /* Prefer IPv4 -- shorter, easier to type */
        List<String> ips = ipv4.isEmpty() ? ipv6 : ipv4;
        StringBuilder sb = new StringBuilder();
        for (String ip : ips) {
            if (sb.length() > 0) sb.append("\n");
            sb.append("simplecipher connect ").append(ip).append(" ").append(port);
        }
        return sb.toString();
    }

    private void disconnect() {
        running = false;
        new Thread(this::nativeDisconnect).start();
    }

    @Override
    public void onBackPressed() {
        /* Clean disconnect when the user presses the back button.
         * Without this, the network thread keeps running and the
         * native session is not wiped. */
        disconnect();
        super.onBackPressed();
    }

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
        if (sasInput != null) sasInput.setText("");
        if (sasCodeText != null) sasCodeText.setText("");
        if (chatLog != null) chatLog.setText("");
        if (chatInput != null) chatInput.setText("");
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
         * Rationale: a backgrounded app with live crypto state in memory
         * is a target for memory-dumping attacks.  Ending the session on
         * stop reduces the exposure window to only the time the user is
         * actively looking at the screen. */
        disconnect();
        if (sasInput != null) sasInput.setText("");
        if (sasCodeText != null) sasCodeText.setText("");
        if (chatLog != null) chatLog.setText("");
        if (chatInput != null) chatInput.setText("");
        super.onStop();
    }

    @Override
    protected void onDestroy() {
        /* Belt-and-suspenders: wipe again in case onStop didn't run
         * (e.g. the system killed the process). */
        disconnect();
        super.onDestroy();
    }
}
