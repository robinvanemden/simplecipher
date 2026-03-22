#!/usr/bin/env bash
# test_android_emulator.sh — Emulator smoke test for SimpleCipher Android
#
# Installs the debug APK on a running emulator, launches MainActivity,
# navigates to ChatActivity via UI, and checks for crashes via logcat.
# Designed to run inside reactivecircus/android-emulator-runner.
#
# Usage: bash tests/test_android_emulator.sh <path-to-apk>

set -euo pipefail

APK="${1:?Usage: $0 <apk-path>}"
PKG="com.example.simplecipher"
MAIN=".MainActivity"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }

check_no_crash() {
    if adb logcat -d -s AndroidRuntime:E | grep -q "FATAL EXCEPTION"; then
        fail "$1"
        echo "--- Crash trace ---"
        adb logcat -d -s AndroidRuntime:E
        echo "-------------------"
    else
        pass "$1"
    fi
}

# Tap a UI element by its resource ID using uiautomator
tap_by_id() {
    local rid="$1"
    local bounds
    bounds=$(adb shell uiautomator dump /dev/stdout 2>/dev/null \
        | grep -oP "resource-id=\"${rid}\"[^>]*bounds=\"\K[^\"]+") || return 1
    local x1 y1 x2 y2
    x1=$(echo "$bounds" | grep -oP '\d+' | sed -n 1p)
    y1=$(echo "$bounds" | grep -oP '\d+' | sed -n 2p)
    x2=$(echo "$bounds" | grep -oP '\d+' | sed -n 3p)
    y2=$(echo "$bounds" | grep -oP '\d+' | sed -n 4p)
    adb shell input tap $(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 ))
}

# ------------------------------------------------------------------
# Install
# ------------------------------------------------------------------
echo "=== Installing APK ==="
adb install -r "$APK"
pass "APK installed"

# ------------------------------------------------------------------
# 1. Launch MainActivity
# ------------------------------------------------------------------
echo ""
echo "=== Launching MainActivity ==="
adb logcat -c
adb shell am start -n "$PKG/$MAIN" -W
sleep 3

if adb shell dumpsys activity activities | grep -q "mResumedActivity.*$PKG"; then
    pass "MainActivity is in foreground"
else
    fail "MainActivity did not reach foreground"
fi

check_no_crash "MainActivity: no crash"

# ------------------------------------------------------------------
# 2. Navigate to ChatActivity via Go button
#    (ChatActivity is exported=false, so we drive it through the UI)
# ------------------------------------------------------------------
echo ""
echo "=== Navigating to ChatActivity (listen mode) ==="
adb logcat -c

# Default mode is "Listen", so just tap Go
if tap_by_id "${PKG}:id/goButton"; then
    sleep 5
    check_no_crash "ChatActivity (listen via UI): no crash"

    # ------------------------------------------------------------------
    # 3. Press Back to trigger onStop / cleanup path
    # ------------------------------------------------------------------
    echo ""
    echo "=== Testing lifecycle (Back press) ==="
    adb logcat -c
    adb shell input keyevent KEYCODE_BACK
    sleep 3
    check_no_crash "Back press: no crash"
else
    fail "Could not find Go button (uiautomator)"
fi

# ------------------------------------------------------------------
# 4. Force-stop and cold re-launch
# ------------------------------------------------------------------
echo ""
echo "=== Cold start test ==="
adb shell am force-stop "$PKG"
sleep 1
adb logcat -c
adb shell am start -n "$PKG/$MAIN" -W
sleep 3

check_no_crash "Cold start: no crash"

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
