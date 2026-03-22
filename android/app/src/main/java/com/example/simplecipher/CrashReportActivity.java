package com.example.simplecipher;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Minimal activity that displays a crash trace.  Uses no XML layouts,
 * no custom themes, no native code — just programmatic views so it
 * can survive even when the main app's resources are broken.
 */
public class CrashReportActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String trace = App.pendingCrashTrace;
        if (trace == null) {
            finish();
            return;
        }

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 64, 32, 32);
        root.setBackgroundColor(0xFF1A1A2E);

        TextView title = new TextView(this);
        title.setText("SimpleCipher crashed");
        title.setTextSize(20);
        title.setTextColor(0xFFFF6B6B);
        title.setPadding(0, 0, 0, 24);
        root.addView(title);

        TextView hint = new TextView(this);
        hint.setText("Copy this trace and share it for debugging:");
        hint.setTextSize(13);
        hint.setTextColor(0xFFAAAAAA);
        hint.setPadding(0, 0, 0, 16);
        root.addView(hint);

        ScrollView scroll = new ScrollView(this);
        TextView traceView = new TextView(this);
        traceView.setText(trace);
        traceView.setTextSize(10);
        traceView.setTextColor(0xFFE0E0E0);
        traceView.setTypeface(android.graphics.Typeface.MONOSPACE);
        traceView.setTextIsSelectable(true);
        scroll.addView(traceView);

        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        scroll.setLayoutParams(scrollParams);
        root.addView(scroll);

        Button copyBtn = new Button(this);
        copyBtn.setText("COPY TO CLIPBOARD");
        copyBtn.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("crash", trace));
            Toast.makeText(this, "Copied!", Toast.LENGTH_SHORT).show();
        });
        root.addView(copyBtn);

        Button dismissBtn = new Button(this);
        dismissBtn.setText("DISMISS");
        dismissBtn.setOnClickListener(v -> {
            App.pendingCrashTrace = null;
            finish();
        });
        root.addView(dismissBtn);

        setContentView(root);
    }
}
