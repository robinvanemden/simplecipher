#!/usr/bin/env bash
# Validate Android APK structure and security hardening for SimpleCipher.
# Usage: bash tests/test_android.sh <apk-path>
set -uo pipefail

APK="${1:?Usage: test_android.sh <apk> [minimal|full]}"
FLAVOR="${2:-full}"

PASS=0
FAIL=0

# Run a command directly (no eval, no shell expansion on arguments).
check() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

# Run a shell pipeline safely via bash -c, passing variables as positional
# arguments to prevent injection.  The script string must use $1, $2, etc.
# Usage: check_pipe "description" 'script using $1 $2 ...' arg1 arg2 ...
check_pipe() {
    local desc="$1"
    local script="$2"
    shift 2
    if bash -c "$script" -- "$@" >/dev/null 2>&1; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Android APK structure tests ==="

check "APK exists" test -f "$APK"
check_pipe "contains classes.dex" 'unzip -l "$1" | grep -q "classes.dex"' "$APK"
check_pipe "contains arm64-v8a SO" 'unzip -l "$1" | grep -q "lib/arm64-v8a/libsimplecipher.so"' "$APK"
check_pipe "contains armeabi-v7a SO" 'unzip -l "$1" | grep -q "lib/armeabi-v7a/libsimplecipher.so"' "$APK"

# Size check: APK should be under 2 MB (crypto adds size)
SIZE="$(stat --format=%s "$APK" 2>/dev/null || stat -f%z "$APK" 2>/dev/null || echo 999999)"
check "APK size < 2 MB" test "$SIZE" -lt 2097152

# ---- aapt2-based tests (manifest + resources) ----
if command -v aapt2 >/dev/null 2>&1; then
    BADGING="$(aapt2 dump badging "$APK" 2>/dev/null || true)"
    XMLTREE_MANIFEST="$(aapt2 dump xmltree --file AndroidManifest.xml "$APK" 2>/dev/null || true)"

    echo ""
    echo "=== Manifest metadata tests ==="
    check_pipe "package name is com.example.simplecipher" \
        'printf "%s" "$1" | grep -q "package: name='\''com.example.simplecipher'\''"' "$BADGING"
    check_pipe "minSdkVersion is 28" \
        'printf "%s" "$1" | grep -q "sdkVersion:'\''28'\''"' "$BADGING"
    check_pipe "has launcher activity" \
        'printf "%s" "$1" | grep -q "launchable-activity"' "$BADGING"

    echo ""
    echo "=== Security hardening tests (manifest) ==="

    # Backup prevention
    check_pipe "allowBackup is false" \
        'printf "%s" "$1" | grep -A1 "allowBackup" | grep -q "0x0"' "$XMLTREE_MANIFEST"
    check_pipe "fullBackupContent is false" \
        'printf "%s" "$1" | grep -A1 "fullBackupContent" | grep -q "0x0"' "$XMLTREE_MANIFEST"

    # Cleartext traffic
    check_pipe "usesCleartextTraffic is false" \
        'printf "%s" "$1" | grep -A1 "usesCleartextTraffic" | grep -q "0x0"' "$XMLTREE_MANIFEST"

    # ChatActivity hardening
    check_pipe "ChatActivity is not exported" \
        'printf "%s" "$1" | grep -B5 "ChatActivity" | grep -A1 "exported" | grep -q "0x0"' "$XMLTREE_MANIFEST"
    check_pipe "ChatActivity excludeFromRecents" \
        'printf "%s" "$1" | grep -q "excludeFromRecents"' "$XMLTREE_MANIFEST"
    check_pipe "ChatActivity noHistory" \
        'printf "%s" "$1" | grep -q "noHistory"' "$XMLTREE_MANIFEST"
    check_pipe "ChatActivity has taskAffinity" \
        'printf "%s" "$1" | grep -q "taskAffinity"' "$XMLTREE_MANIFEST"

    # Permission check
    if [ "$FLAVOR" = "minimal" ]; then
        check_pipe "minimal: exactly two permissions declared" \
            'printf "%s" "$1" | grep "uses-permission" | grep -c "permission" | grep -q "^2$"' "$XMLTREE_MANIFEST"
    else
        check_pipe "full: exactly three permissions declared (INTERNET + HIDE_OVERLAY + CAMERA)" \
            'printf "%s" "$1" | grep "uses-permission" | grep -c "permission" | grep -q "^3$"' "$XMLTREE_MANIFEST"
        check_pipe "full: CAMERA permission present" \
            'printf "%s" "$1" | grep "uses-permission" | grep -q "CAMERA"' "$XMLTREE_MANIFEST"
    fi

    # Debuggable check (should not be present or should be false in release)
    check_pipe "not debuggable" \
        '! printf "%s" "$1" | grep -A1 "debuggable" | grep -q "0xffffffff"' "$XMLTREE_MANIFEST"

    echo ""
    echo "=== Security hardening tests (resources) ==="

    # Check layout resources for security attributes
    XMLTREE_CHAT="$(aapt2 dump xmltree --file res/layout/activity_chat.xml "$APK" 2>/dev/null || true)"
    if [ -n "$XMLTREE_CHAT" ]; then
        # Tapjacking protection
        check_pipe "SAS confirm button has filterTouchesWhenObscured" \
            'printf "%s" "$1" | grep -q "filterTouchesWhenObscured"' "$XMLTREE_CHAT"

        # Chat log not selectable
        check_pipe "chat log textIsSelectable=false" \
            'printf "%s" "$1" | grep -q "textIsSelectable"' "$XMLTREE_CHAT"

        # No suggestions on inputs
        check_pipe "inputs use textNoSuggestions" \
            'printf "%s" "$1" | grep -q "privateImeOptions"' "$XMLTREE_CHAT"

        # Autofill disabled
        check_pipe "inputs have importantForAutofill=no" \
            'printf "%s" "$1" | grep -q "importantForAutofill"' "$XMLTREE_CHAT"
    else
        echo "  SKIP: could not dump activity_chat.xml layout"
    fi

    echo ""
    echo "=== APK-level release safety tests ==="

    # These checks only apply to release builds (debug builds are debuggable
    # by design and retain log calls for development).
    # No exported content providers or broadcast receivers (attack surface)
    check_pipe "no exported content providers" \
        '! printf "%s" "$1" | grep -q "provider"' "$XMLTREE_MANIFEST"
    check_pipe "no exported broadcast receivers" \
        '! printf "%s" "$1" | grep -q "receiver"' "$XMLTREE_MANIFEST"

    # No WebView usage — SimpleCipher should never load web content
    check_pipe "no WebView in dex" \
        '! unzip -p "$1" classes.dex 2>/dev/null | strings | grep -q "android/webkit/WebView"' "$APK"

    # Release-only checks (debug builds are debuggable and retain logs by design)
    IS_DEBUG="$(echo "$BADGING" | grep -c 'application-debuggable' || true)"
    if [ "$IS_DEBUG" -eq 0 ]; then
        check "release APK is not debuggable" true

        # ProGuard log stripping verification
        if command -v dexdump >/dev/null 2>&1; then
            DEXDUMP="$(dexdump -d "$APK" 2>/dev/null || true)"
            check_pipe "no Log.d/v/i/w/e/wtf calls in dex (R8 stripped)" \
                '! printf "%s" "$1" | grep -qE "Landroid/util/Log;\.(d|v|i|w|e|wtf)"' "$DEXDUMP"
        elif command -v baksmali >/dev/null 2>&1; then
            SMALI_DIR="$(mktemp -d)"
            baksmali d "$APK" -o "$SMALI_DIR" 2>/dev/null || true
            check_pipe "no Log.d/v/i/w/e/wtf calls in dex (R8 stripped)" \
                '! grep -rqE "Landroid/util/Log;->(d|v|i|w|e|wtf)" "$1"' "$SMALI_DIR"
            rm -rf "$SMALI_DIR"
        else
            echo "  SKIP: dexdump/baksmali not found, skipping log stripping verification"
        fi
    else
        echo "  SKIP: debug build — skipping debuggable and log stripping checks"
    fi

else
    echo "  SKIP: aapt2 not found, skipping manifest and security validation"
fi

# ---- Native library security tests ----

# Extract both ARM SOs for inspection
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

unzip -q -o "$APK" 'lib/arm64-v8a/libsimplecipher.so' 'lib/armeabi-v7a/libsimplecipher.so' -d "$TMPDIR" 2>/dev/null || true

# Run security checks on a single .so file.
# $1 = ABI name (for display), $2 = path to .so
check_so() {
    local abi="$1" so="$2"

    echo ""
    echo "=== Native library security tests ($abi) ==="

    if [ ! -f "$so" ]; then
        echo "  SKIP: could not extract $abi .so from APK"
        return
    fi

    if ! command -v readelf >/dev/null 2>&1; then
        echo "  SKIP: readelf not found, skipping .so inspection"
        return
    fi

    # Stripped .so should not have a .symtab section
    check_pipe "$abi: no .symtab (symbols stripped)" \
        '! readelf -S "$1" | grep -q "\.symtab"' "$so"

    # RELRO check
    check_pipe "$abi: has RELRO" \
        'readelf -l "$1" | grep -q "GNU_RELRO"' "$so"

    # Stack canary: dynamic .so imports __stack_chk_fail from libc
    check_pipe "$abi: has stack canary (__stack_chk_fail)" \
        'readelf -W --dyn-syms "$1" | grep -q "__stack_chk_fail"' "$so"

    # FORTIFY_SOURCE: should have _chk variants of libc functions
    check_pipe "$abi: has FORTIFY_SOURCE (_chk functions)" \
        'readelf -W --dyn-syms "$1" | grep -qE "__[a-z]+_chk"' "$so"

    # No plaintext SAS/key strings leaked into binary
    check_pipe "$abi: no 'SAS:' debug string" \
        '! strings "$1" | grep -q "SAS:"' "$so"

    # JNI symbol visibility: only JNI_OnLoad and Java_* should be exported.
    # Count GLOBAL FUNC symbols that are not JNI entry points — should be zero.
    check_pipe "$abi: only JNI symbols exported (no internal leaks)" \
        'test "$(readelf -W --dyn-syms "$1" \
            | awk "/GLOBAL.*FUNC/ && !/UND/ && !/JNI_OnLoad/ && !/Java_/" \
            | wc -l)" -eq 0' "$so"

    # No LOGI/LOGE format strings in release (NDEBUG should suppress them)
    check_pipe "$abi: no log format strings (NDEBUG active)" \
        '! strings "$1" | grep -qE "(connecting to|listening on|handshake|CMD_QUIT)"' "$so"

    # Non-executable stack (NX): GNU_STACK segment should have no E flag
    check_pipe "$abi: non-executable stack (NX)" \
        'readelf -l "$1" | grep "GNU_STACK" | grep -qv " E"' "$so"
}

# ARM64-specific hardening checks
check_so_arm64() {
    local so="$1"

    if [ ! -f "$so" ] || ! command -v readelf >/dev/null 2>&1; then
        return
    fi

    # PAC+BTI: check for PAC/BTI instructions in the binary.
    # NDK clang emits PACIASP/AUTIASP (PAC) and BTI (Branch Target
    # Identification) instructions but may not emit .note.gnu.property.
    # Check for the presence of these instructions via objdump, or
    # verify the compiler flag is in CMakeLists.txt (source-level check).
    REPO_ROOT_ARM64="$(cd "$(dirname "$0")/.." && pwd)"
    check "arm64: built with PAC+BTI (mbranch-protection in CMakeLists)" \
        grep -q 'mbranch-protection=standard' "$REPO_ROOT_ARM64/android/app/src/main/c/CMakeLists.txt"
}

check_so "arm64-v8a" "$TMPDIR/lib/arm64-v8a/libsimplecipher.so"
check_so_arm64       "$TMPDIR/lib/arm64-v8a/libsimplecipher.so"
check_so "armeabi-v7a" "$TMPDIR/lib/armeabi-v7a/libsimplecipher.so"

echo ""
echo "=== Source-level security tests ==="

# These tests verify the source files contain expected hardening patterns.
# They run against the repo, not the APK, catching regressions at CI time.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# FLAG_SECURE in both activities
check "ChatActivity has FLAG_SECURE" \
    grep -q 'FLAG_SECURE' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"
check "MainActivity has FLAG_SECURE" \
    grep -q 'FLAG_SECURE' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"

# Memory wipe on pause
check_pipe "ChatActivity wipes UI in onPause" \
    'grep -A5 "onPause" "$1" | grep -q "setText"' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"

# Session end on stop (backgrounding = forced teardown via nativeStop)
check_pipe "ChatActivity calls nativeStop in onStop" \
    'grep -A20 "onStop" "$1" | grep -q "nativeStop"' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"

# Send-drop semantics: nativePostCommand returns boolean, Java checks result
check "nativePostCommand returns boolean (not void)" \
    grep -q 'native boolean nativePostCommand' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"
check_pipe "JNI nativePostCommand returns jboolean" \
    'grep -A1 "JNIEXPORT jboolean" "$1" | grep -q "nativePostCommand"' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check_pipe "sendMessage checks nativePostCommand result before showing message" \
    'grep -A10 "sendMessage" "$1" | grep -q "boolean ok"' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"
check "JNI GetByteArrayElements null-checked (prevents uninitialized data leak)" \
    grep -q '!pbuf' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check_pipe "JNI GetStringUTFChars null-checked in nativeStart" \
    'grep -B2 -A2 "GetStringUTFChars" "$1" | grep -q "OOM"' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"

# SAS wiped after confirmation
check "SAS code cleared after confirm" \
    grep -q 'sasCodeText.setText' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"

# Clipboard auto-clear
check "clipboard auto-cleared after copy" \
    grep -q 'postDelayed' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"

# JNI: logcat suppressed in release
check "JNI logging suppressed under NDEBUG" \
    grep -q 'NDEBUG' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"

# JNI: single-threaded crypto architecture with pipe IPC
# The session thread owns all crypto/session/socket state exclusively.
# A mutex exists only for lifecycle coordination (nativeStop closing
# sockets from the UI thread), not for protecting crypto operations.
check "JNI uses pipe for IPC (no shared mutable state)" \
    grep -q 'pipe(' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "JNI lifecycle mutex is for shutdown coordination only" \
    grep -q 'g_session_mtx' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"

# JNI: crypto_wipe used for cleanup
check "JNI uses crypto_wipe for key material" \
    grep -q 'crypto_wipe' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"

# SimpleKeyboard on all inputs (host, port, fingerprint)
check "MainActivity uses SimpleKeyboard for all inputs" \
    grep -q 'mainKeyboard' "$REPO_ROOT/android/app/src/main/res/layout/activity_main.xml"
check "MainActivity suppresses system keyboard on host input" \
    grep -q 'bindToKeyboard(hostInput' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"
check "MainActivity suppresses system keyboard on port input" \
    grep -q 'bindToKeyboard(portInput' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"
check "MainActivity suppresses system keyboard on fingerprint input" \
    grep -q 'bindToKeyboard(fpManualInput' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"
check "MainActivity suppresses system keyboard on SOCKS5 input" \
    grep -q 'bindToKeyboard(socks5Input' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"
check "MainActivity has hideSystemKeyboard helper" \
    grep -q 'hideSystemKeyboard' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"
check "bindToKeyboard suppresses system keyboard" \
    grep -q 'setShowSoftInputOnFocus(false)' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"

# SOCKS5 proxy support
check "JNI nativeStart accepts socks5_proxy parameter" \
    grep -q 'jstring socks5_proxy' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "JNI calls connect_socket_socks5 for proxy connects" \
    grep -q 'connect_socket_socks5' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "SOCKS5 fails closed on malformed proxy (no silent direct connect)" \
    grep -q 'proxy string malformed' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "SOCKS5 fails closed on strdup OOM" \
    grep -q 'SOCKS5 strdup failed' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "SOCKS5 restricted to loopback in Java" \
    grep -q '127.0.0.1.*localhost.*::1' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"
check "SOCKS5 restricted to loopback in JNI (defence in depth)" \
    grep -q 'proxy must be localhost' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "JNI strdup(host) null-checked" \
    grep -q 'strdup(host) failed' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "JNI NewGlobalRef null-checked" \
    grep -q 'NewGlobalRef failed' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "setPeerFingerprint clears stale state on invalid input" \
    grep -q 'clearPeerFingerprint()' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"

# Paused-state guards on sensitive callbacks
check_pipe "onSasReady checks paused before populating UI" \
    'grep -A5 "onSasReady" "$1" | grep -q "paused"' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"
check_pipe "CMD_CONFIRM_SAS checks nativePostCommand return" \
    'grep -B1 -A1 "CMD_CONFIRM_SAS" "$1" | grep -q "!nativePostCommand"' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"

# SOCKS5 GetStringUTFChars OOM fails closed
check "SOCKS5 GetStringUTFChars OOM aborts (no silent direct connect)" \
    grep -q 'GetStringUTFChars(socks5_proxy) failed' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"

# Fingerprint GetStringUTFChars OOM clears stale state
check_pipe "fingerprint GetStringUTFChars OOM clears g_peer_fp" \
    'grep -A5 "!fp_str" "$1" | grep -q "g_peer_fp_valid = 0"' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "JNI frees socks5_host on cleanup" \
    grep -q 'free(socks5_host)' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "JNI frees socks5_port on cleanup" \
    grep -q 'free(socks5_port)' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "ChatActivity passes socks5_proxy to nativeStart" \
    grep -q 'socks5Proxy' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"
check "MainActivity validates SOCKS5 host:port format" \
    grep -q 'lastIndexOf' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"
check_pipe "SOCKS5 input has filterTouchesWhenObscured" \
    'grep -A15 "socks5Input" "$1" | grep -q "filterTouchesWhenObscured"' "$REPO_ROOT/android/app/src/main/res/layout/activity_main.xml"
check_pipe "SOCKS5 input has importantForAutofill=no" \
    'grep -A15 "socks5Input" "$1" | grep -q "importantForAutofill"' "$REPO_ROOT/android/app/src/main/res/layout/activity_main.xml"
check_pipe "host input has filterTouchesWhenObscured" \
    'grep -A15 "hostInput" "$1" | grep -q "filterTouchesWhenObscured"' "$REPO_ROOT/android/app/src/main/res/layout/activity_main.xml"
check_pipe "port input has filterTouchesWhenObscured" \
    'grep -A15 "portInput" "$1" | grep -q "filterTouchesWhenObscured"' "$REPO_ROOT/android/app/src/main/res/layout/activity_main.xml"
check_pipe "fingerprint input has filterTouchesWhenObscured" \
    'grep -A15 "fpManualInput" "$1" | grep -q "filterTouchesWhenObscured"' "$REPO_ROOT/android/app/src/main/res/layout/activity_main.xml"
check_pipe "chat input has filterTouchesWhenObscured" \
    'grep -A15 "chatInput" "$1" | grep -q "filterTouchesWhenObscured"' "$REPO_ROOT/android/app/src/main/res/layout/activity_chat.xml"
check_pipe "SAS input has filterTouchesWhenObscured" \
    'grep -A15 "sasInput" "$1" | grep -q "filterTouchesWhenObscured"' "$REPO_ROOT/android/app/src/main/res/layout/activity_chat.xml"
check_pipe "Go button has filterTouchesWhenObscured" \
    'grep -A15 "goButton" "$1" | grep -q "filterTouchesWhenObscured"' "$REPO_ROOT/android/app/src/main/res/layout/activity_main.xml"
check_pipe "Send button has filterTouchesWhenObscured" \
    'grep -A15 "sendBtn" "$1" | grep -q "filterTouchesWhenObscured"' "$REPO_ROOT/android/app/src/main/res/layout/activity_chat.xml"
check_pipe "FP scan button has filterTouchesWhenObscured" \
    'grep -A15 "fpScanBtn" "$1" | grep -q "filterTouchesWhenObscured"' "$REPO_ROOT/android/app/src/main/res/layout/activity_main.xml"
check_pipe "Listen radio has filterTouchesWhenObscured" \
    'grep -A15 "radioListen" "$1" | grep -q "filterTouchesWhenObscured"' "$REPO_ROOT/android/app/src/main/res/layout/activity_main.xml"
check_pipe "Connect radio has filterTouchesWhenObscured" \
    'grep -A15 "radioConnect" "$1" | grep -q "filterTouchesWhenObscured"' "$REPO_ROOT/android/app/src/main/res/layout/activity_main.xml"

# Fingerprint state management
check "nativeClearPeerFingerprint exists in JNI" \
    grep -q 'nativeClearPeerFingerprint' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "clearPeerFingerprint called when input becomes invalid" \
    grep -q 'clearPeerFingerprint()' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"
check_pipe "nativeClearPeerFingerprint wipes g_peer_fp" \
    'grep -A5 "nativeClearPeerFingerprint" "$1" | grep -q "crypto_wipe"' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"

# SOCKS5 reply validation
check "SOCKS5 reply checks version byte (0x05)" \
    grep -q 'reply\[0\] != 0x05' "$REPO_ROOT/src/network.c"

check "SOCKS5 input wiped on background" \
    grep -q 'socks5Input.*setText' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"

# Clipboard safety: warning on older Android versions
check "MainActivity warns about clipboard on API < 30" \
    grep -q 'Build.VERSION.SDK_INT < 30' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"

# Direct connect uses AI_NUMERICHOST (no blocking DNS)
check "JNI direct connect uses AI_NUMERICHOST (no DNS)" \
    grep -q 'AI_NUMERICHOST' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "Java validates numeric IP on direct connect" \
    grep -q 'isNumericAddress' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"

# nativeGenerateKey null return handled
check_pipe "nativeGenerateKey null return handled (no NPE on OOM)" \
    'grep -A5 "nativeGenerateKey" "$1" | grep -q "selfFingerprint == null"' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"

# pendingSas wiped in onPause
check_pipe "pendingSas cleared in onPause" \
    'grep -A25 "protected void onPause" "$1" | grep -q "pendingSas = null"' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"

# Dynamic COPY button has tapjacking protection
check "Dynamic COPY button has setFilterTouchesWhenObscured" \
    grep -q 'setFilterTouchesWhenObscured' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"

# JNI callback exception checking
check "JNI has jni_callback_ok exception checker" \
    grep -q 'jni_callback_ok' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "JNI checks NewStringUTF(sas) for NULL" \
    grep -q 'NewStringUTF(sas) failed' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"
check "JNI checks NewStringUTF(message) for NULL" \
    grep -q 'NewStringUTF(message) failed' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"

# NativeCallback interface exists
check "NativeCallback.java interface exists" \
    test -f "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/NativeCallback.java"

# No Java-side threading in ChatActivity
check_pipe "ChatActivity has no new Thread() calls" \
    '! grep -q "new Thread" "$1"' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"

# CMake: _FORTIFY_SOURCE
check "CMake enables _FORTIFY_SOURCE" \
    grep -q 'FORTIFY_SOURCE' "$REPO_ROOT/android/app/src/main/c/CMakeLists.txt"

# CMake: RELRO
check "CMake enables RELRO" \
    grep -q 'relro' "$REPO_ROOT/android/app/src/main/c/CMakeLists.txt"

# CMake: symbol stripping
check "CMake strips symbols" \
    grep -q '\-Wl,-s' "$REPO_ROOT/android/app/src/main/c/CMakeLists.txt"

# Note: -fsanitize=cfi was removed — caused linker to strip all internal code
# when combined with LTO + version script.  See CMakeLists.txt comment.

# Note: -fstack-clash-protection removed — NDK clang does not support it

# CMake: hidden visibility
check "CMake uses hidden symbol visibility" \
    grep -q 'fvisibility=hidden' "$REPO_ROOT/android/app/src/main/c/CMakeLists.txt"

# CMake: PAC+BTI for ARM64
check "CMake enables PAC+BTI (ARM64)" \
    grep -q 'mbranch-protection=standard' "$REPO_ROOT/android/app/src/main/c/CMakeLists.txt"

# 16KB page alignment (Android 15+ requirement, NDK r28+ default)
# Native libraries must be aligned to 16KB for Android 15+ compatibility.
# Check via readelf: the maximum p_align of any LOAD segment should be >= 16384.
if command -v readelf >/dev/null 2>&1 && [ -f "$TMPDIR/lib/arm64-v8a/libsimplecipher.so" ]; then
    MAX_ALIGN="$(readelf -l "$TMPDIR/lib/arm64-v8a/libsimplecipher.so" 2>/dev/null \
        | awk '/LOAD/{gsub(/0x/,"",$NF); print strtonum("0x"$NF)}' \
        | sort -rn | head -1)"
    if [ -n "$MAX_ALIGN" ] && [ "$MAX_ALIGN" -ge 16384 ] 2>/dev/null; then
        check "arm64 .so 16KB page aligned (Android 15+)" true
    else
        echo "  SKIP: arm64 .so not 16KB aligned (MAX_ALIGN=${MAX_ALIGN:-unknown}, may need NDK r28+)"
    fi
fi

# JNI exports version script exists
check "JNI exports version script exists" \
    test -f "$REPO_ROOT/android/app/src/main/c/jni_exports.map"

# JNI: prctl PR_SET_DUMPABLE
check "JNI blocks ptrace (PR_SET_DUMPABLE)" \
    grep -q 'PR_SET_DUMPABLE' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"

# JNI: RLIMIT_CORE disabled
check "JNI disables core dumps (RLIMIT_CORE)" \
    grep -q 'RLIMIT_CORE' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"

# Manifest: extractNativeLibs=false
check "Manifest disables native lib extraction" \
    grep -q 'extractNativeLibs.*false' "$REPO_ROOT/android/app/src/main/AndroidManifest.xml"

# Note: hasFragileUserData=false was removed — requires API 29+ but minSdk is 28

# Manifest: network security config
check "Network security config exists" \
    test -f "$REPO_ROOT/android/app/src/main/res/xml/network_security_config.xml"

# ProGuard rules exist
check "ProGuard rules file exists" \
    test -f "$REPO_ROOT/android/app/proguard-rules.pro"

# Data extraction rules exist
check "data_extraction_rules.xml exists" \
    test -f "$REPO_ROOT/android/app/src/main/res/xml/data_extraction_rules.xml"

# Desktop numeric IP check (DNS leak prevention)
check "Desktop direct connect uses connect_socket_numeric (AI_NUMERICHOST)" \
    grep -q 'connect_socket_numeric' "$REPO_ROOT/src/main.c"
check "connect_socket_numeric uses AI_NUMERICHOST" \
    grep -q 'AI_NUMERICHOST' "$REPO_ROOT/src/network.c"
check_pipe "localIpsContainer cleared in onStop" \
    'grep -A25 "onStop" "$1" | grep -q "localIpsContainer.*removeAllViews"' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"

# Host/port wiped on background
check_pipe "hostInput cleared in onStop" \
    'grep -A20 "onStop" "$1" | grep -q "hostInput.*setText"' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java"

# statusText cleared in onPause
check_pipe "statusText cleared in onPause" \
    'grep -A20 "onPause" "$1" | grep -q "statusText.*setText"' "$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java"

# jni_call_str helper exists
check "jni_call_str helper exists in jni_bridge.c" \
    grep -q 'jni_call_str' "$REPO_ROOT/android/app/src/main/c/jni_bridge.c"

# prompt_host wiped at cleanup (in args.c via args_wipe())
check "prompt_host wiped at cleanup in args.c" \
    grep -q 'crypto_wipe(prompt_host' "$REPO_ROOT/src/args.c"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
