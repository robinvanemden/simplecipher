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
    private Thread networkThread;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                             WindowManager.LayoutParams.FLAG_SECURE);
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

        chatLog.setMovementMethod(new ScrollingMovementMethod());

        String mode = getIntent().getStringExtra("mode");
        String host = getIntent().getStringExtra("host");
        int port    = getIntent().getIntExtra("port", 7777);

        boolean isConnect = "connect".equals(mode);

        if (isConnect) {
            statusText.setText("Connecting to " + host + ":" + port + "...");
        } else {
            String ips = getLocalIps();
            statusText.setText("Waiting on port " + port + "\n"
                + (ips.isEmpty() ? "No network" : "Tell peer to connect to:\n" + ips));
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

                sasConfirmBtn.setOnClickListener(v -> {
                    String typed = sasInput.getText().toString().trim().toUpperCase(Locale.ROOT);
                    String expected = sas.substring(0, 4).toUpperCase(Locale.ROOT);
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

                    /* Wire send button */
                    sendBtn.setOnClickListener(sv -> sendMessage());
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
        String ts = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
        String line = "[" + ts + "] " + who + ": " + msg + "\n";
        chatLog.append(line);
        /* Auto-scroll to bottom */
        int scrollAmount = chatLog.getLayout().getLineTop(chatLog.getLineCount())
                           - chatLog.getHeight();
        if (scrollAmount > 0) chatLog.scrollTo(0, scrollAmount);
    }

    private String getLocalIps() {
        List<String> ips = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                    if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()) continue;
                    String ip = addr.getHostAddress();
                    if (addr instanceof Inet6Address) ip = ip.replaceAll("%.*", "");
                    ips.add(ip);
                }
            }
        } catch (Exception ignored) {}
        StringBuilder sb = new StringBuilder();
        for (String ip : ips) {
            if (sb.length() > 0) sb.append("\n");
            sb.append(ip);
        }
        return sb.toString();
    }

    private void disconnect() {
        running = false;
        new Thread(this::nativeDisconnect).start();
    }

    @Override
    protected void onPause() {
        /* Wipe sensitive text from UI widgets so it doesn't linger in the
         * Java heap while the app is backgrounded or in the recent-apps list. */
        if (sasInput != null) sasInput.setText("");
        if (sasCodeText != null) sasCodeText.setText("");
        if (chatLog != null) chatLog.setText("");
        if (chatInput != null) chatInput.setText("");
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (sasInput != null) sasInput.setText("");
        if (sasCodeText != null) sasCodeText.setText("");
        if (chatLog != null) chatLog.setText("");
        if (chatInput != null) chatInput.setText("");
        disconnect();
        super.onDestroy();
    }
}
