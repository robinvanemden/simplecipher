# Keep JNI native methods (called from C via JNI)
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep Application subclass (referenced from AndroidManifest.xml)
-keep public class com.example.simplecipher.App { *; }

# Keep Activity classes and all their members (JNI calls back into these)
-keep public class com.example.simplecipher.MainActivity { *; }
-keep public class com.example.simplecipher.ChatActivity { *; }
-keep public class com.example.simplecipher.CrashReportActivity { *; }

# Keep the NativeCallback interface and all its methods.
# The native thread calls these via JNI GetMethodID by name —
# if R8 renames or strips them, the native code crashes.
# All 7 callbacks: onConnected, onConnectionFailed, onSasReady,
# onHandshakeFailed, onMessageReceived, onSendResult, onDisconnected.
-keep interface com.example.simplecipher.NativeCallback { *; }

# Keep SimpleKeyboard — inflated from activity_chat.xml via class name
# (LayoutInflater uses reflection: Class.forName + Constructor(Context, AttributeSet))
-keep public class com.example.simplecipher.SimpleKeyboard { *; }

# Keep inner/anonymous/synthetic classes (lambdas, listeners).
# Parent { *; } implicitly covers these, but explicit rules defend
# against R8 edge cases in a security-critical app.
-keep class com.example.simplecipher.ChatActivity$* { *; }
-keep class com.example.simplecipher.MainActivity$* { *; }
-keep class com.example.simplecipher.SimpleKeyboard$* { *; }

# Remove ALL logging in release builds — no log output should leak
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
}
