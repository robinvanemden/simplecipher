# Keep JNI native methods (called from C via JNI)
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep Activity classes referenced in AndroidManifest.xml
-keep public class com.example.simplecipher.MainActivity
-keep public class com.example.simplecipher.ChatActivity

# Remove debug logging in release builds
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
}
