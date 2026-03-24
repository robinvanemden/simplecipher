# Android App — SimpleCipher

> **Audience:** Users, developers, and auditors of the SimpleCipher Android app.

## Overview

The Android app provides the same ephemeral encrypted chat as the desktop CLI, with a touch interface. No account, no server, no data stored to disk. The app is a thin Java UI layer over the same C protocol code that runs on desktop — compiled natively via the NDK.

## Architecture

```
┌──────────────────────────────────────────────┐
│  Java (UI)                                   │
│  ┌────────────┐  ┌────────────┐              │
│  │ MainActivity│  │ChatActivity│              │
│  │ (connect)   │  │(SAS + chat)│              │
│  └─────┬──────┘  └─────┬──────┘              │
│        │               │                     │
│        │  NativeCallback (interface)          │
│        │       ▲                              │
│        │       │ callbacks on UI thread       │
├────────┼───────┼─────────────────────────────┤
│  C (Native, via JNI)                         │
│        │       │                              │
│        ▼       │                              │
│  ┌─────────────┴──────────┐                  │
│  │  Single native thread   │                 │
│  │  ┌─────────┐ ┌────────┐│                  │
│  │  │protocol │ │ crypto ││                  │
│  │  │network  │ │ratchet ││                  │
│  │  └─────────┘ └────────┘│                  │
│  └─────────────────────────┘                 │
│        ▲                                     │
│        │ command pipe (atomic writes)         │
│        │                                     │
│  nativePostCommand(cmd, payload)             │
└──────────────────────────────────────────────┘
```

**Why single-threaded native:** All crypto, session, and socket state lives on one native thread. Java communicates through a POSIX pipe. No mutexes, no shared mutable state, no possibility of nonce reuse or race conditions. See [the design spec](superpowers/specs/2026-03-22-android-single-thread-native-design.md) for the rationale.

## Security Measures

### What the app does

| Measure | Why |
|---------|-----|
| `FLAG_SECURE` | Prevents screenshots and screen recording of chat and SAS screens |
| `HIDE_OVERLAY_WINDOWS` | Blocks screen-overlay attacks that could read the safety code |
| `IME_FLAG_NO_PERSONALIZED_LEARNING` | Asks the system keyboard not to learn from typed text |
| Custom `SimpleKeyboard` | Bypasses the system keyboard entirely for SAS input and chat — no keystroke logging by third-party IMEs |
| Session kill on `onStop()` | Backgrounding the app kills the session and wipes keys — prevents background sniffing |
| Widget clearing on `onPause()` | Best-effort wipe of text fields when leaving the foreground |
| `crypto_wipe()` in native | All keys and secrets are zeroed in C after use, on every exit path |
| No persistent storage | Nothing written to disk — no databases, no SharedPreferences for keys, no logs |

### What the app cannot guarantee

The JVM manages memory with garbage collection. Java Strings are immutable and cannot be reliably zeroed — a message or key that passed through a Java String may linger in heap memory until the GC reclaims it. The native layer wipes everything it touches, but the Java-to-native boundary involves String objects that are outside our control.

For the strongest memory guarantees, use the desktop CLI or TUI.

## Verification Methods

SimpleCipher offers two ways to verify you're talking to the right person. Both are optional but strongly recommended — without verification, a man-in-the-middle attack goes undetected.

### Safety code (SAS) — default

After connecting, both sides see the same 8-character hex code (e.g., `A3F2-91BC`). Compare it out-of-band — read it aloud on a video or voice call. If it matches, type it in to confirm. If it doesn't match, disconnect immediately.

This requires a live channel at connection time but no advance preparation.

### Fingerprint QR exchange — optional, stronger

Each side generates an ephemeral fingerprint (16-character hex code derived from the session's public key). This fingerprint can be displayed as a QR code and scanned by the peer before connecting. After the handshake, the fingerprint is verified automatically — no manual code comparison needed.

**Why it's stronger than SAS:**
- 64 bits of entropy (fingerprint) vs 32 bits (SAS)
- Cryptographic verification, not human comparison — no "it looks close enough" mistakes
- Verification happens automatically after handshake — cannot be accidentally skipped

**Why the fingerprint is safe to share:**
- It's derived from the public key, which is exchanged openly during the handshake
- A lost or intercepted fingerprint is useless — an attacker cannot forge a key that produces the same fingerprint
- The fingerprint is ephemeral — it changes every session, so a printed QR code works exactly once

**Paper exchange (in person):**
1. Both open the app and expand the "Fingerprint verification" section
2. Each person's fingerprint appears as a QR code on screen
3. Scan each other's QR codes (or printed copies)
4. Tap "Start" — the handshake runs and fingerprints are verified automatically

**Video call exchange:**
1. Both open the app and expand the "Fingerprint verification" section
2. Alice holds her phone screen to the webcam — Bob scans it
3. Bob holds his phone screen to the webcam — Alice scans it
4. Both tap "Start" — same automatic verification

**Without a camera:** Type the fingerprint manually in the text field below the scan button. The CLI equivalent is `--peer-fingerprint XXXX-XXXX-XXXX-XXXX`.

## Screens

### Connect screen (MainActivity)

Choose Listen or Connect. Enter host and port for connect mode. Optionally expand the fingerprint section to exchange QR codes before connecting.

In listen mode, the app displays all local IP addresses with ready-to-copy connection commands.

### Chat screen (ChatActivity)

After connecting, the SAS verification screen appears (unless fingerprints were already verified, in which case it shows a confirmation and proceeds directly to chat).

Chat uses a custom on-screen keyboard (`SimpleKeyboard`) that never touches the system IME. Messages are displayed with timestamps in a scrollable log.

Pressing back, backgrounding the app, or losing the connection ends the session and wipes all keys.

## Building

```bash
# Debug build
cd android && ./gradlew assembleDebug

# Release build (requires signing config)
cd android && ./gradlew assembleRelease

# Run tests
cd android && ./gradlew connectedAndroidTest
```

**Requirements:**
- Android Studio or standalone Gradle
- NDK 28.0.13004108 (specified in `app/build.gradle`)
- SDK 35 (compile), min SDK 28 (Android 9+)
- CMake for NDK builds

**Release ABIs:** `arm64-v8a`, `armeabi-v7a` (covers ~99% of Android devices). CI adds `x86_64` for emulator testing.

**Hardening flags (native):** `-std=c23 -Os -flto -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fvisibility=hidden` with full RELRO and no lazy binding. Only JNI entry points are exported (via `jni_exports.map`).

## Permissions

| Permission | When requested | Required |
|------------|---------------|----------|
| `INTERNET` | Always (TCP connection) | Yes |
| `CAMERA` | When user taps "Scan peer fingerprint" | No — only for QR scanning, runtime request |

No storage, contacts, location, microphone, or background permissions. The app does nothing in the background.

## Dependencies

| Dependency | Purpose | License |
|------------|---------|---------|
| Monocypher (vendored C) | All cryptography | BSD-2-Clause / CC0 |
| ZXing core | QR code generation | Apache 2.0 |
| ZXing Android embedded | QR code scanning with camera | Apache 2.0 |

No Google Play Services dependency. Works on all Android devices including degoogled phones (LineageOS, GrapheneOS, etc.).

## File Map

```
android/
├── app/
│   ├── src/main/
│   │   ├── java/com/example/simplecipher/
│   │   │   ├── MainActivity.java        Connect/listen screen, fingerprint QR
│   │   │   ├── ChatActivity.java        SAS verification, chat, auto-verify
│   │   │   ├── NativeCallback.java      Java ↔ native callback interface
│   │   │   └── SimpleKeyboard.java      Custom keyboard (HEX + QWERTY)
│   │   ├── c/
│   │   │   └── jni_bridge.c             Single-threaded native layer
│   │   ├── res/layout/
│   │   │   ├── activity_main.xml        Connect screen layout
│   │   │   └── activity_chat.xml        Chat screen layout
│   │   └── AndroidManifest.xml
│   ├── build.gradle                     Dependencies, SDK versions, ABIs
│   └── src/main/c/CMakeLists.txt        NDK build config
└── build.gradle                         Project-level Gradle config
```
