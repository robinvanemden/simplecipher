# Keep JNI native methods (called from C via JNI)
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep Activity classes and all their members (JNI calls back into these)
-keep public class com.example.simplecipher.MainActivity { *; }
-keep public class com.example.simplecipher.ChatActivity { *; }

# Keep the NativeCallback interface and all its methods.
# The native thread calls these via JNI GetMethodID by name —
# if R8 renames or strips them, the native code crashes.
-keep interface com.example.simplecipher.NativeCallback { *; }

# Keep SimpleKeyboard (referenced programmatically from ChatActivity
# and potentially from activity_chat.xml via class name)
-keep public class com.example.simplecipher.SimpleKeyboard { *; }

# Remove debug logging in release builds
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
}
