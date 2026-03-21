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

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MainActivity extends Activity {

    private RadioGroup    modeGroup;
    private TextView      connectLabel;
    private EditText      hostInput;
    private EditText      portInput;
    private LinearLayout  localIpsContainer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                             WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_main);

        modeGroup        = findViewById(R.id.modeGroup);
        connectLabel     = findViewById(R.id.connectLabel);
        hostInput        = findViewById(R.id.hostInput);
        portInput        = findViewById(R.id.portInput);
        localIpsContainer = findViewById(R.id.localIpsContainer);
        Button goButton  = findViewById(R.id.goButton);

        showLocalIps();

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
        label.setText(ips.size() == 1 ? "Your local IP" : "Your local IPs");
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        label.setTextColor(0xFF666666);
        label.setPadding(dp(4), 0, 0, dp(8));
        localIpsContainer.addView(label);

        for (int i = 0; i < ips.size(); i++) {
            String ip = ips.get(i);

            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dp(16), dp(12), dp(12), dp(12));
            row.setBackgroundResource(R.drawable.bg_ip_row);

            /* IP text */
            TextView ipText = new TextView(this);
            ipText.setText(ip);
            ipText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
            ipText.setTextColor(0xFFF0F0F0);
            ipText.setTypeface(android.graphics.Typeface.MONOSPACE);
            ipText.setLetterSpacing(0.03f);
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
                cm.setPrimaryClip(ClipData.newPlainText("IP address", ip));
                Toast.makeText(this, "Copied " + ip, Toast.LENGTH_SHORT).show();
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
        return ips;
    }
}
