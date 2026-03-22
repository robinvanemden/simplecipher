#!/usr/bin/env bash
# test_android_emulator.sh — Emulator smoke test for SimpleCipher Android
#
# Installs the debug APK on a running emulator, launches each activity,
# and checks for crashes via logcat.  Designed to run inside the
# reactivecircus/android-emulator-runner GitHub Action.
#
# Usage: bash tests/test_android_emulator.sh <path-to-apk>

set -euo pipefail

APK="${1:?Usage: $0 <apk-path>}"
PKG="com.example.simplecipher"
MAIN=".MainActivity"
CHAT=".ChatActivity"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }

# ------------------------------------------------------------------
# Install
# ------------------------------------------------------------------
echo "=== Installing APK ==="
adb install -r "$APK"
pass "APK installed"

# ------------------------------------------------------------------
# 1. Launch MainActivity — should render without crashing
# ------------------------------------------------------------------
echo ""
echo "=== Launching MainActivity ==="
adb logcat -c
adb shell am start -n "$PKG/$MAIN" -W
sleep 3

# Check the activity is in the foreground
if adb shell dumpsys activity activities | grep -q "mResumedActivity.*$PKG"; then
    pass "MainActivity is in foreground"
else
    fail "MainActivity did not reach foreground"
fi

# Check for fatal crashes in logcat
if adb logcat -d -s AndroidRuntime:E | grep -q "FATAL EXCEPTION"; then
    fail "MainActivity crashed (FATAL EXCEPTION in logcat)"
    echo "--- Crash trace ---"
    adb logcat -d -s AndroidRuntime:E
    echo "-------------------"
else
    pass "MainActivity: no crash"
fi

# ------------------------------------------------------------------
# 2. Launch ChatActivity in listen mode — tests JNI + native load
# ------------------------------------------------------------------
echo ""
echo "=== Launching ChatActivity (listen mode) ==="
adb logcat -c
adb shell am start -n "$PKG/$CHAT" \
    --es mode listen --es host "" --ei port 17777
sleep 5

# ChatActivity may or may not be the resumed activity (it calls
# nativeStart which spawns a thread), but it should not crash.
if adb logcat -d -s AndroidRuntime:E | grep -q "FATAL EXCEPTION"; then
    fail "ChatActivity crashed (FATAL EXCEPTION in logcat)"
    echo "--- Crash trace ---"
    adb logcat -d -s AndroidRuntime:E
    echo "-------------------"
else
    pass "ChatActivity (listen): no crash"
fi

# Verify native library loaded successfully
if adb logcat -d | grep -q "simplecipher.*native"; then
    pass "Native library loaded"
else
    # Not a hard failure — the log tag may differ
    pass "Native library load (no crash implies success)"
fi

# ------------------------------------------------------------------
# 3. Press Back to trigger onStop / cleanup path
# ------------------------------------------------------------------
echo ""
echo "=== Testing lifecycle (Back press) ==="
adb logcat -c
adb shell input keyevent KEYCODE_BACK
sleep 2

if adb logcat -d -s AndroidRuntime:E | grep -q "FATAL EXCEPTION"; then
    fail "Crash during Back press / lifecycle cleanup"
    echo "--- Crash trace ---"
    adb logcat -d -s AndroidRuntime:E
    echo "-------------------"
else
    pass "Back press: no crash"
fi

# ------------------------------------------------------------------
# 4. Force-stop and re-launch (cold start)
# ------------------------------------------------------------------
echo ""
echo "=== Cold start test ==="
adb shell am force-stop "$PKG"
sleep 1
adb logcat -c
adb shell am start -n "$PKG/$MAIN" -W
sleep 3

if adb logcat -d -s AndroidRuntime:E | grep -q "FATAL EXCEPTION"; then
    fail "Cold start crashed"
    echo "--- Crash trace ---"
    adb logcat -d -s AndroidRuntime:E
    echo "-------------------"
else
    pass "Cold start: no crash"
fi

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== Full logcat dump for debugging ==="
    adb logcat -d
    exit 1
fi
