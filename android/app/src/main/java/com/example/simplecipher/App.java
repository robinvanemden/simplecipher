package com.example.simplecipher;

import android.app.Application;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Application subclass that installs a crash handler before any Activity
 * runs.  On crash, the stack trace is written to crash.txt in the app's
 * private directory.  MainActivity reads and displays it on next launch.
 */
public class App extends Application {
    @Override
    public void onCreate() {
        super.onCreate();

        final File crashFile = new File(getFilesDir(), "crash.txt");
        final Thread.UncaughtExceptionHandler defaultHandler =
                Thread.getDefaultUncaughtExceptionHandler();

        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            try {
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                FileWriter fw = new FileWriter(crashFile);
                fw.write("Thread: " + t.getName() + "\n\n" + sw.toString());
                fw.close();
            } catch (Exception ignored) {}
            if (defaultHandler != null) defaultHandler.uncaughtException(t, e);
        });
    }
}
