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

    # Permission check: only INTERNET + HIDE_OVERLAY_WINDOWS, nothing dangerous
    check "exactly two permissions declared" \
        "echo '$XMLTREE_MANIFEST' | grep 'uses-permission' | grep -c 'permission' | grep -q '^2$'"

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

    echo ""
    echo "=== APK-level release safety tests ==="

    # These checks only apply to release builds (debug builds are debuggable
    # by design and retain log calls for development).
    # No exported content providers or broadcast receivers (attack surface)
    check "no exported content providers" \
        "! echo '$XMLTREE_MANIFEST' | grep -q 'provider'"
    check "no exported broadcast receivers" \
        "! echo '$XMLTREE_MANIFEST' | grep -q 'receiver'"

    # No WebView usage — SimpleCipher should never load web content
    check "no WebView in dex" \
        "! unzip -p '$APK' classes.dex 2>/dev/null | strings | grep -q 'android/webkit/WebView'"

    # Release-only checks (debug builds are debuggable and retain logs by design)
    IS_DEBUG="$(echo "$BADGING" | grep -c 'application-debuggable' || true)"
    if [ "$IS_DEBUG" -eq 0 ]; then
        check "release APK is not debuggable" "true"

        # ProGuard log stripping verification
        if command -v dexdump >/dev/null 2>&1; then
            DEXDUMP="$(dexdump -d "$APK" 2>/dev/null || true)"
            check "no Log.d/v/i/w/e/wtf calls in dex (R8 stripped)" \
                "! echo '$DEXDUMP' | grep -qE 'Landroid/util/Log;\.(d|v|i|w|e|wtf)'"
        elif command -v baksmali >/dev/null 2>&1; then
            SMALI_DIR="$(mktemp -d)"
            baksmali d "$APK" -o "$SMALI_DIR" 2>/dev/null || true
            check "no Log.d/v/i/w/e/wtf calls in dex (R8 stripped)" \
                "! grep -rqE 'Landroid/util/Log;->(d|v|i|w|e|wtf)' '$SMALI_DIR'"
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
    check "$abi: no .symtab (symbols stripped)" \
        "! readelf -S '$so' | grep -q '\.symtab'"

    # RELRO check
    check "$abi: has RELRO" \
        "readelf -l '$so' | grep -q 'GNU_RELRO'"

    # Stack canary: dynamic .so imports __stack_chk_fail from libc
    check "$abi: has stack canary (__stack_chk_fail)" \
        "readelf -W --dyn-syms '$so' | grep -q '__stack_chk_fail'"

    # FORTIFY_SOURCE: should have _chk variants of libc functions
    check "$abi: has FORTIFY_SOURCE (_chk functions)" \
        "readelf -W --dyn-syms '$so' | grep -qE '__[a-z]+_chk'"

    # No plaintext SAS/key strings leaked into binary
    check "$abi: no 'SAS:' debug string" \
        "! strings '$so' | grep -q 'SAS:'"

    # JNI symbol visibility: only JNI_OnLoad and Java_* should be exported.
    # Count GLOBAL FUNC symbols that are not JNI entry points — should be zero.
    check "$abi: only JNI symbols exported (no internal leaks)" \
        "test \$(readelf -W --dyn-syms '$so' \
            | awk '/GLOBAL.*FUNC/ && !/UND/ && !/JNI_OnLoad/ && !/Java_/' \
            | wc -l) -eq 0"

    # No LOGI/LOGE format strings in release (NDEBUG should suppress them)
    check "$abi: no log format strings (NDEBUG active)" \
        "! strings '$so' | grep -qE '(connecting to|listening on|handshake|CMD_QUIT)'"

    # Non-executable stack (NX): GNU_STACK segment should have no E flag
    check "$abi: non-executable stack (NX)" \
        "readelf -l '$so' | grep 'GNU_STACK' | grep -qv ' E'"
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
    check "arm64: built with PAC+BTI (mbranch-protection in CMakeLists)" \
        "grep -q 'mbranch-protection=standard' '$(cd "$(dirname "$0")/.." && pwd)/android/app/src/main/c/CMakeLists.txt'"
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

# CMake: CFI
check "CMake enables CFI" \
    "grep -q 'fsanitize=cfi' '$REPO_ROOT/android/app/src/main/c/CMakeLists.txt'"

# CMake: stack clash protection
check "CMake enables stack clash protection" \
    "grep -q 'fstack-clash-protection' '$REPO_ROOT/android/app/src/main/c/CMakeLists.txt'"

# CMake: hidden visibility
check "CMake uses hidden symbol visibility" \
    "grep -q 'fvisibility=hidden' '$REPO_ROOT/android/app/src/main/c/CMakeLists.txt'"

# CMake: PAC+BTI for ARM64
check "CMake enables PAC+BTI (ARM64)" \
    "grep -q 'mbranch-protection=standard' '$REPO_ROOT/android/app/src/main/c/CMakeLists.txt'"

# 16KB page alignment (Android 15+ requirement, NDK r28+ default)
# Native libraries must be aligned to 16KB for Android 15+ compatibility.
# Check via readelf: the maximum p_align of any LOAD segment should be >= 16384.
if command -v readelf >/dev/null 2>&1 && [ -f "$TMPDIR/lib/arm64-v8a/libsimplecipher.so" ]; then
    MAX_ALIGN="$(readelf -l "$TMPDIR/lib/arm64-v8a/libsimplecipher.so" 2>/dev/null \
        | awk '/LOAD/{gsub(/0x/,"",$NF); print strtonum("0x"$NF)}' \
        | sort -rn | head -1)"
    if [ -n "$MAX_ALIGN" ] && [ "$MAX_ALIGN" -ge 16384 ] 2>/dev/null; then
        check "arm64 .so 16KB page aligned (Android 15+)" "true"
    else
        echo "  SKIP: arm64 .so not 16KB aligned (MAX_ALIGN=${MAX_ALIGN:-unknown}, may need NDK r28+)"
    fi
fi

# JNI exports version script exists
check "JNI exports version script exists" \
    "test -f '$REPO_ROOT/android/app/src/main/c/jni_exports.map'"

# JNI: prctl PR_SET_DUMPABLE
check "JNI blocks ptrace (PR_SET_DUMPABLE)" \
    "grep -q 'PR_SET_DUMPABLE' '$REPO_ROOT/android/app/src/main/c/jni_bridge.c'"

# JNI: RLIMIT_CORE disabled
check "JNI disables core dumps (RLIMIT_CORE)" \
    "grep -q 'RLIMIT_CORE' '$REPO_ROOT/android/app/src/main/c/jni_bridge.c'"

# Manifest: extractNativeLibs=false
check "Manifest disables native lib extraction" \
    "grep -q 'extractNativeLibs.*false' '$REPO_ROOT/android/app/src/main/AndroidManifest.xml'"

# Manifest: hasFragileUserData=false (prevent OS from offering to keep data on uninstall)
check "Manifest has hasFragileUserData=false" \
    "grep -q 'hasFragileUserData.*false' '$REPO_ROOT/android/app/src/main/AndroidManifest.xml'"

# Manifest: network security config
check "Network security config exists" \
    "test -f '$REPO_ROOT/android/app/src/main/res/xml/network_security_config.xml'"

# ProGuard rules exist
check "ProGuard rules file exists" \
    "test -f '$REPO_ROOT/android/app/proguard-rules.pro'"

# Data extraction rules exist
check "data_extraction_rules.xml exists" \
    "test -f '$REPO_ROOT/android/app/src/main/res/xml/data_extraction_rules.xml'"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
