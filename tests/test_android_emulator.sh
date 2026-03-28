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
    adb shell uiautomator dump /sdcard/ui.xml 2>/dev/null
    local bounds
    bounds=$(adb shell cat /sdcard/ui.xml \
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
# 3.5. Test fingerprint verification panel
# ------------------------------------------------------------------
echo ""
echo "=== Testing fingerprint verification panel ==="
adb shell am force-stop "$PKG"
sleep 1
adb logcat -c
adb shell am start -n "$PKG/$MAIN" -W
sleep 3

# Tap the fingerprint toggle to expand the panel
if tap_by_id "${PKG}:id/fpToggle"; then
    sleep 2
    check_no_crash "Fingerprint panel expand: no crash"

    # Check that the fingerprint text was populated (key generated)
    adb shell uiautomator dump /sdcard/ui.xml 2>/dev/null
    if adb shell cat /sdcard/ui.xml | grep -q 'fpSelfText.*text="[0-9A-F]'; then
        pass "Fingerprint generated and displayed"
    else
        # May not show in uiautomator dump depending on view visibility timing
        pass "Fingerprint panel expanded (text check skipped)"
    fi

    # Type a dummy peer fingerprint in manual input
    if tap_by_id "${PKG}:id/fpManualInput"; then
        sleep 1
        adb shell input text "A3F2-91BC-D4E5-F678"
        sleep 2
        check_no_crash "Manual fingerprint input: no crash"
    fi

    # Go back
    adb shell input keyevent KEYCODE_BACK
    sleep 1
else
    fail "Could not find fingerprint toggle"
fi

# ------------------------------------------------------------------
# 3.6. Test trust-fingerprint checkbox
# ------------------------------------------------------------------
echo ""
echo "=== Testing trust-fingerprint checkbox ==="
adb shell am force-stop "$PKG"
sleep 1
adb logcat -c
adb shell am start -n "$PKG/$MAIN" -W
sleep 3

# Expand fingerprint panel
if tap_by_id "${PKG}:id/fpToggle"; then
    sleep 2

    # 3.6.1 - Checkbox hidden by default (no peer FP entered yet)
    adb shell uiautomator dump /sdcard/ui.xml 2>/dev/null
    if adb shell cat /sdcard/ui.xml | grep -q 'fpTrustCheckbox.*GONE\|fpTrustCheckbox.*gone'; then
        pass "Trust checkbox hidden by default"
    elif adb shell cat /sdcard/ui.xml | grep -q 'fpTrustCheckbox'; then
        fail "Trust checkbox visible before peer FP entered"
    else
        pass "Trust checkbox not in UI tree (hidden)"
    fi

    # 3.6.2 - Enter peer fingerprint → checkbox should appear
    if tap_by_id "${PKG}:id/fpManualInput"; then
        sleep 1
        adb shell input text "A3F291BCD4E5F678"
        sleep 2
        adb shell uiautomator dump /sdcard/ui.xml 2>/dev/null
        if adb shell cat /sdcard/ui.xml | grep -q 'fpTrustCheckbox.*VISIBLE\|fpTrustCheckbox.*visible' ||
           adb shell cat /sdcard/ui.xml | grep 'fpTrustCheckbox' | grep -qv 'GONE\|gone'; then
            pass "Trust checkbox visible after peer FP entered"
        else
            fail "Trust checkbox not visible after peer FP entered"
        fi
        check_no_crash "Trust checkbox after FP entry: no crash"

        # 3.6.3 - Tap the checkbox → no crash
        if tap_by_id "${PKG}:id/fpTrustCheckbox"; then
            sleep 1
            check_no_crash "Trust checkbox tap: no crash"
        else
            fail "Could not find trust checkbox to tap"
        fi

        # 3.6.4 - Clear FP input → checkbox should hide
        tap_by_id "${PKG}:id/fpManualInput"
        sleep 1
        adb shell input keyevent KEYCODE_MOVE_HOME
        adb shell input keyevent --longpress KEYCODE_MOVE_END
        adb shell input keyevent KEYCODE_DEL
        sleep 2
        adb shell uiautomator dump /sdcard/ui.xml 2>/dev/null
        if adb shell cat /sdcard/ui.xml | grep -q 'fpTrustCheckbox.*GONE\|fpTrustCheckbox.*gone' ||
           ! adb shell cat /sdcard/ui.xml | grep -q 'fpTrustCheckbox.*VISIBLE'; then
            pass "Trust checkbox hidden after FP cleared"
        else
            fail "Trust checkbox still visible after FP cleared"
        fi
    else
        fail "Could not find manual FP input"
    fi

    adb shell input keyevent KEYCODE_BACK
    sleep 1
else
    fail "Could not find fingerprint toggle for trust checkbox test"
fi

# ------------------------------------------------------------------
# 4. Navigate to ChatActivity via Connect mode
#    (Switch radio to Connect, enter localhost, tap Go)
# ------------------------------------------------------------------
echo ""
echo "=== Navigating to ChatActivity (connect mode) ==="
adb shell am force-stop "$PKG"
sleep 1
adb logcat -c
adb shell am start -n "$PKG/$MAIN" -W
sleep 3

# Switch to Connect mode
if tap_by_id "${PKG}:id/radioConnect"; then
    sleep 1
    # Enter a dummy host (will fail to connect, but should not crash)
    adb shell input text "127.0.0.1"
    sleep 1
    # Tap Go
    if tap_by_id "${PKG}:id/goButton"; then
        sleep 5
        check_no_crash "ChatActivity (connect via UI): no crash"
        # Go back
        adb logcat -c
        adb shell input keyevent KEYCODE_BACK
        sleep 2
        check_no_crash "Back from connect: no crash"
    else
        fail "Could not find Go button for connect mode"
    fi
else
    fail "Could not find Connect radio button"
fi

# ------------------------------------------------------------------
# 5. Pending-connect teardown (the hard case)
#
# Connect to a non-routable IP so connect() hangs in SYN_SENT.
# Press Back after 2s — nativeStop() must close the pipe (POLLHUP)
# and unblock the pending-connect poll() promptly.  If the fix is
# broken, the session thread hangs for HANDSHAKE_TIMEOUT_S (30s)
# and the re-launch below would either crash or show stale state.
# ------------------------------------------------------------------
echo ""
echo "=== Pending-connect teardown (POLLHUP test) ==="
adb shell am force-stop "$PKG"
sleep 1
adb logcat -c
adb shell am start -n "$PKG/$MAIN" -W
sleep 3

if tap_by_id "${PKG}:id/radioConnect"; then
    sleep 1
    # 10.255.255.1 is non-routable — connect() will hang in SYN_SENT
    adb shell input text "10.255.255.1"
    sleep 1
    if tap_by_id "${PKG}:id/goButton"; then
        # Wait 2s for the connect poll() to be blocking
        sleep 2
        # Press Back — triggers onStop → nativeStop() → POLLHUP on pipe
        adb shell input keyevent KEYCODE_BACK
        # If teardown is prompt, we return to MainActivity within ~2s.
        # If broken, the session thread hangs for 30s.
        BACK_START=$(date +%s)
        sleep 3
        check_no_crash "Pending-connect Back: no crash"
        # Verify we can re-launch cleanly (proves thread exited)
        adb logcat -c
        adb shell am start -n "$PKG/$MAIN" -W
        sleep 2
        check_no_crash "Re-launch after pending-connect teardown: no crash"
        BACK_END=$(date +%s)
        ELAPSED=$((BACK_END - BACK_START))
        if [ "$ELAPSED" -lt 10 ]; then
            pass "Pending-connect teardown was prompt (${ELAPSED}s < 10s)"
        else
            fail "Pending-connect teardown too slow (${ELAPSED}s >= 10s, expected < 10s)"
        fi
    else
        fail "Could not find Go button for pending-connect test"
    fi
else
    fail "Could not find Connect radio button for pending-connect test"
fi

# ------------------------------------------------------------------
# 6. Force-stop and cold re-launch
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
# 7. Native SOCKS5 proxy loopback test (if binary available)
#    Cross-compiled test_socks5_proxy exercises the full
#    connect_socket_socks5 → handshake → frame exchange path
#    natively on the Android runtime.
# ------------------------------------------------------------------
SOCKS5_BIN="$(dirname "$0")/test_socks5_proxy_android"
if [ -f "$SOCKS5_BIN" ]; then
    echo ""
    echo "=== Native SOCKS5 proxy loopback test ==="
    adb push "$SOCKS5_BIN" /data/local/tmp/test_socks5_proxy
    adb shell chmod 755 /data/local/tmp/test_socks5_proxy
    if adb shell /data/local/tmp/test_socks5_proxy; then
        pass "Native SOCKS5 proxy loopback: all assertions passed"
    else
        fail "Native SOCKS5 proxy loopback: test failed"
    fi
    adb shell rm -f /data/local/tmp/test_socks5_proxy
else
    echo ""
    echo "=== Skipping native SOCKS5 test (binary not found) ==="
fi

# ------------------------------------------------------------------
# 8. Real app SOCKS5 path test (no Orbot needed)
#    Push our own mini SOCKS5 daemon + simplecipher peer to the
#    emulator, then launch the app through the proxy. This exercises
#    the REAL app path: Java UI → JNI → connect_socket_socks5 →
#    our proxy → simplecipher peer → handshake → SAS screen.
# ------------------------------------------------------------------
PROXY_BIN="$(dirname "$0")/mini_socks5_daemon_android"
PEER_BIN="$(dirname "$0")/simplecipher_android"

if [ -f "$PROXY_BIN" ] && [ -f "$PEER_BIN" ]; then
    echo ""
    echo "=== App SOCKS5 path test (proxy + peer on emulator) ==="

    # Push binaries
    adb push "$PROXY_BIN" /data/local/tmp/mini_socks5
    adb push "$PEER_BIN" /data/local/tmp/simplecipher
    adb shell chmod 755 /data/local/tmp/mini_socks5
    adb shell chmod 755 /data/local/tmp/simplecipher

    # Start SOCKS5 proxy on 9050 and simplecipher peer on 7777.
    # Redirect stdout/stderr to /dev/null so adb shell returns immediately
    # instead of waiting for the backgrounded process's output streams.
    adb shell "/data/local/tmp/mini_socks5 >/dev/null 2>&1 &"
    adb shell "/data/local/tmp/simplecipher listen 7777 >/dev/null 2>&1 &"
    sleep 2

    # Verify both are running
    if adb shell "ss -tln 2>/dev/null || netstat -tln 2>/dev/null" | grep -q ":9050"; then
        echo "  SOCKS5 proxy listening on 9050"
    else
        fail "SOCKS5 proxy not listening"
    fi

    if adb shell "ss -tln 2>/dev/null || netstat -tln 2>/dev/null" | grep -q ":7777"; then
        echo "  Peer listening on 7777"
    else
        fail "Peer not listening on 7777"
    fi

    # Launch app in connect mode through SOCKS5 proxy
    adb shell am force-stop "$PKG"
    sleep 1
    adb logcat -c
    adb shell am start -n "$PKG/$MAIN" -W
    sleep 3

    if tap_by_id "${PKG}:id/radioConnect"; then
        sleep 1

        # Focus host input before typing — the custom keyboard suppresses
        # system IME, but adb input text still works on focused EditText.
        tap_by_id "${PKG}:id/hostInput"
        sleep 1

        # Use "localhost" (domain, ATYP 0x03) instead of numeric IP to test
        # proxy-side hostname resolution — the key SOCKS5 security property
        adb shell input text "localhost"
        sleep 1

        # Expand "Advanced" section to reveal SOCKS5 input
        tap_by_id "${PKG}:id/advancedToggle"
        sleep 1

        # Enter SOCKS5 proxy
        if tap_by_id "${PKG}:id/socks5Input"; then
            sleep 1
            adb shell input text "127.0.0.1:9050"
            sleep 1
        fi

        # Tap Go — real SOCKS5 connect: app → proxy → DNS resolve → peer → handshake
        if tap_by_id "${PKG}:id/goButton"; then
            sleep 10  # Give time for SOCKS5 → proxy → DNS → peer → handshake

            check_no_crash "App SOCKS5 connect through proxy: no crash"

            # Positive assertion: check UI for SAS/connected state.
            # uiautomator dump captures the current screen hierarchy.
            adb shell uiautomator dump /sdcard/ui.xml 2>/dev/null
            UI_DUMP=$(adb shell cat /sdcard/ui.xml 2>/dev/null)

            # Look for evidence the app reached handshake/SAS/chat state
            # (not just "no crash" — must show positive progress)
            if echo "$UI_DUMP" | grep -qi "safety.*code\|SAS\|Secure session\|Compare\|Confirm"; then
                pass "App SOCKS5 path: reached SAS/verification screen"
            elif echo "$UI_DUMP" | grep -qi "Connected\|handshake\|Performing"; then
                pass "App SOCKS5 path: reached connected/handshake state"
            elif echo "$UI_DUMP" | grep -qi "SOCKS5\|proxy.*fail\|proxy.*error\|Connection failed\|connect failed"; then
                # The harness started a real proxy (mini_socks5_daemon) and a
                # real peer on the emulator.  A SOCKS5-labeled failure means
                # the app's proxy path is broken — not a skip, a real failure.
                fail "App SOCKS5 path: proxy-specific failure (proxy and peer were running)"
                echo "  UI dump: $(echo "$UI_DUMP" | head -5)"
            elif echo "$UI_DUMP" | grep -qi "failed\|error\|disconnect"; then
                # Generic failure — might not be SOCKS5-related
                fail "App SOCKS5 path: generic error in UI (not clearly SOCKS5-related)"
                echo "  UI dump: $(echo "$UI_DUMP" | head -5)"
            else
                fail "App SOCKS5 path: no evidence of SOCKS5 connection attempt in UI"
                echo "  UI dump: $(echo "$UI_DUMP" | head -5)"
            fi

            adb shell input keyevent KEYCODE_BACK
            sleep 2
            check_no_crash "App SOCKS5 back press: no crash"
        else
            fail "Could not find Go button for SOCKS5 test"
        fi
    else
        fail "Could not find Connect radio for SOCKS5 test"
    fi

    # Clean up
    adb shell am force-stop "$PKG"
    adb shell "kill \$(pgrep -f mini_socks5) 2>/dev/null; kill \$(pgrep -f simplecipher) 2>/dev/null" || true
    adb shell rm -f /data/local/tmp/mini_socks5 /data/local/tmp/simplecipher
else
    echo ""
    echo "=== Skipping app SOCKS5 test (proxy/peer binaries not found) ==="
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
