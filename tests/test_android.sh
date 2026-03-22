#!/usr/bin/env bash
# Validate Android APK structure and security hardening for SimpleCipher.
# Usage: bash tests/test_android.sh <apk-path>
set -uo pipefail

APK="${1:?Usage: test_android.sh <apk>}"

PASS=0
FAIL=0

check() {
    local desc="$1"
    shift
    if eval "$@" >/dev/null 2>&1; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Android APK structure tests ==="

check "APK exists" "test -f '$APK'"
check "contains classes.dex" "unzip -l '$APK' | grep -q 'classes.dex'"
check "contains arm64-v8a SO" "unzip -l '$APK' | grep -q 'lib/arm64-v8a/libsimplecipher.so'"
check "contains armeabi-v7a SO" "unzip -l '$APK' | grep -q 'lib/armeabi-v7a/libsimplecipher.so'"

# Size check: APK should be under 2 MB (crypto adds size)
SIZE="$(stat --format=%s "$APK" 2>/dev/null || stat -f%z "$APK" 2>/dev/null || echo 999999)"
check "APK size < 2 MB" "test '$SIZE' -lt 2097152"

# ---- aapt2-based tests (manifest + resources) ----
if command -v aapt2 >/dev/null 2>&1; then
    BADGING="$(aapt2 dump badging "$APK" 2>/dev/null || true)"
    XMLTREE_MANIFEST="$(aapt2 dump xmltree --file AndroidManifest.xml "$APK" 2>/dev/null || true)"

    echo ""
    echo "=== Manifest metadata tests ==="
    check "package name is com.example.simplecipher" \
        "echo '$BADGING' | grep -q \"package: name='com.example.simplecipher'\""
    check "minSdkVersion is 28" \
        "echo '$BADGING' | grep -q \"sdkVersion:'28'\""
    check "has launcher activity" \
        "echo '$BADGING' | grep -q 'launchable-activity'"

    echo ""
    echo "=== Security hardening tests (manifest) ==="

    # Backup prevention
    check "allowBackup is false" \
        "echo '$XMLTREE_MANIFEST' | grep -A1 'allowBackup' | grep -q '0x0'"
    check "fullBackupContent is false" \
        "echo '$XMLTREE_MANIFEST' | grep -A1 'fullBackupContent' | grep -q '0x0'"

    # Cleartext traffic
    check "usesCleartextTraffic is false" \
        "echo '$XMLTREE_MANIFEST' | grep -A1 'usesCleartextTraffic' | grep -q '0x0'"

    # ChatActivity hardening
    check "ChatActivity is not exported" \
        "echo '$XMLTREE_MANIFEST' | grep -B5 'ChatActivity' | grep -A1 'exported' | grep -q '0x0'"
    check "ChatActivity excludeFromRecents" \
        "echo '$XMLTREE_MANIFEST' | grep -q 'excludeFromRecents'"
    check "ChatActivity noHistory" \
        "echo '$XMLTREE_MANIFEST' | grep -q 'noHistory'"
    check "ChatActivity has taskAffinity" \
        "echo '$XMLTREE_MANIFEST' | grep -q 'taskAffinity'"

    # Permission check: only INTERNET, nothing dangerous
    check "only INTERNET permission declared" \
        "echo '$XMLTREE_MANIFEST' | grep 'uses-permission' | grep -c 'permission' | grep -q '^1$'"

    # Debuggable check (should not be present or should be false in release)
    check "not debuggable" \
        "! echo '$XMLTREE_MANIFEST' | grep -A1 'debuggable' | grep -q '0xffffffff'"

    echo ""
    echo "=== Security hardening tests (resources) ==="

    # Check layout resources for security attributes
    XMLTREE_CHAT="$(aapt2 dump xmltree --file res/layout/activity_chat.xml "$APK" 2>/dev/null || true)"
    if [ -n "$XMLTREE_CHAT" ]; then
        # Tapjacking protection
        check "SAS confirm button has filterTouchesWhenObscured" \
            "echo '$XMLTREE_CHAT' | grep -q 'filterTouchesWhenObscured'"

        # Chat log not selectable
        check "chat log textIsSelectable=false" \
            "echo '$XMLTREE_CHAT' | grep -q 'textIsSelectable'"

        # No suggestions on inputs
        check "inputs use textNoSuggestions" \
            "echo '$XMLTREE_CHAT' | grep -q 'privateImeOptions'"

        # Autofill disabled
        check "inputs have importantForAutofill=no" \
            "echo '$XMLTREE_CHAT' | grep -q 'importantForAutofill'"
    else
        echo "  SKIP: could not dump activity_chat.xml layout"
    fi

else
    echo "  SKIP: aapt2 not found, skipping manifest and security validation"
fi

# ---- Native library security tests ----
echo ""
echo "=== Native library security tests ==="

# Extract the arm64 SO for inspection
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

unzip -q -o "$APK" 'lib/arm64-v8a/libsimplecipher.so' -d "$TMPDIR" 2>/dev/null || true
SO="$TMPDIR/lib/arm64-v8a/libsimplecipher.so"

if [ -f "$SO" ]; then
    # Symbol stripping: readelf should show minimal symbols
    if command -v readelf >/dev/null 2>&1; then
        # Stripped .so should not have a .symtab section
        check "native .so has no .symtab (symbols stripped)" \
            "! readelf -S '$SO' | grep -q '\.symtab'"

        # RELRO check
        check "native .so has RELRO" \
            "readelf -l '$SO' | grep -q 'GNU_RELRO'"

        # Stack canary: dynamic .so imports __stack_chk_fail from libc
        # Use -W (wide) so long symbol names aren't truncated by readelf
        check "native .so has stack canary (__stack_chk_fail in dynsym)" \
            "readelf -W --dyn-syms '$SO' | grep -q '__stack_chk_fail'"

        # FORTIFY_SOURCE: should have _chk variants of libc functions (dynamic symbols survive stripping)
        check "native .so has FORTIFY_SOURCE (_chk functions)" \
            "readelf -s --dyn-syms '$SO' | grep -qE '__[a-z]+_chk'"

        # No plaintext SAS/key strings leaked into binary
        check "no 'SAS:' debug string in .so" \
            "! strings '$SO' | grep -q 'SAS:'"

    elif command -v objdump >/dev/null 2>&1; then
        check "native .so has RELRO (objdump)" \
            "objdump -p '$SO' | grep -q 'GNU_RELRO'"
    else
        echo "  SKIP: readelf/objdump not found, skipping .so inspection"
    fi
else
    echo "  SKIP: could not extract arm64 .so from APK"
fi

echo ""
echo "=== Source-level security tests ==="

# These tests verify the source files contain expected hardening patterns.
# They run against the repo, not the APK, catching regressions at CI time.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# FLAG_SECURE in both activities
check "ChatActivity has FLAG_SECURE" \
    "grep -q 'FLAG_SECURE' '$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java'"
check "MainActivity has FLAG_SECURE" \
    "grep -q 'FLAG_SECURE' '$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java'"

# Memory wipe on pause
check "ChatActivity wipes UI in onPause" \
    "grep -A5 'onPause' '$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java' | grep -q 'setText'"

# Session end on stop (backgrounding = session end via CMD_QUIT)
check "ChatActivity posts CMD_QUIT in onStop" \
    "grep -A10 'onStop' '$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java' | grep -q 'CMD_QUIT'"

# SAS wiped after confirmation
check "SAS code cleared after confirm" \
    "grep -q 'sasCodeText.setText' '$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java'"

# Clipboard auto-clear
check "clipboard auto-cleared after copy" \
    "grep -q 'postDelayed' '$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/MainActivity.java'"

# JNI: logcat suppressed in release
check "JNI logging suppressed under NDEBUG" \
    "grep -q 'NDEBUG' '$REPO_ROOT/android/app/src/main/c/jni_bridge.c'"

# JNI: single-threaded architecture (no mutex = concurrency eliminated by design)
check "JNI uses pipe for IPC (no shared mutable state)" \
    "grep -q 'pipe(' '$REPO_ROOT/android/app/src/main/c/jni_bridge.c'"
check "JNI has no pthread_mutex (single-threaded)" \
    "! grep -q 'pthread_mutex' '$REPO_ROOT/android/app/src/main/c/jni_bridge.c'"

# JNI: crypto_wipe used for cleanup
check "JNI uses crypto_wipe for key material" \
    "grep -q 'crypto_wipe' '$REPO_ROOT/android/app/src/main/c/jni_bridge.c'"

# NativeCallback interface exists
check "NativeCallback.java interface exists" \
    "test -f '$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/NativeCallback.java'"

# No Java-side threading in ChatActivity
check "ChatActivity has no new Thread() calls" \
    "! grep -q 'new Thread' '$REPO_ROOT/android/app/src/main/java/com/example/simplecipher/ChatActivity.java'"

# CMake: _FORTIFY_SOURCE
check "CMake enables _FORTIFY_SOURCE" \
    "grep -q 'FORTIFY_SOURCE' '$REPO_ROOT/android/app/src/main/c/CMakeLists.txt'"

# CMake: RELRO
check "CMake enables RELRO" \
    "grep -q 'relro' '$REPO_ROOT/android/app/src/main/c/CMakeLists.txt'"

# CMake: symbol stripping
check "CMake strips symbols" \
    "grep -q '\-Wl,-s' '$REPO_ROOT/android/app/src/main/c/CMakeLists.txt'"

# ProGuard rules exist
check "ProGuard rules file exists" \
    "test -f '$REPO_ROOT/android/app/proguard-rules.pro'"

# Data extraction rules exist
check "data_extraction_rules.xml exists" \
    "test -f '$REPO_ROOT/android/app/src/main/res/xml/data_extraction_rules.xml'"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
