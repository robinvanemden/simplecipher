package com.example.simplecipher;

import android.app.Application;
import android.content.Intent;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Application subclass that installs a crash handler before any Activity
 * runs.  On crash, the stack trace is written to both internal and external
 * storage.  On next launch, if a crash file exists, CrashReportActivity is
 * launched instead of MainActivity so the user can read and copy the trace.
 */
public class App extends Application {

    static String pendingCrashTrace = null;

    @Override
    public void onCreate() {
        super.onCreate();

        /* Write crash to both internal and external (file manager visible) dirs */
        final File internalCrash = new File(getFilesDir(), "crash.txt");
        final File externalCrash = getExternalFilesDir(null) != null
                ? new File(getExternalFilesDir(null), "crash.txt") : null;

        /* Check for crash report from previous run BEFORE any Activity starts */
        if (internalCrash.exists()) {
            try {
                byte[] bytes = java.nio.file.Files.readAllBytes(internalCrash.toPath());
                pendingCrashTrace = new String(bytes);
                internalCrash.delete();
                if (externalCrash != null) externalCrash.delete();
            } catch (Exception ignored) {
                internalCrash.delete();
            }
        }

        final Thread.UncaughtExceptionHandler defaultHandler =
                Thread.getDefaultUncaughtExceptionHandler();

        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            try {
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                String trace = "Thread: " + t.getName() + "\n\n" + sw.toString();

                FileWriter fw = new FileWriter(internalCrash);
                fw.write(trace);
                fw.close();

                if (externalCrash != null) {
                    externalCrash.getParentFile().mkdirs();
                    FileWriter fw2 = new FileWriter(externalCrash);
                    fw2.write(trace);
                    fw2.close();
                }
            } catch (Exception ignored) {}
            if (defaultHandler != null) defaultHandler.uncaughtException(t, e);
        });
    }
}
