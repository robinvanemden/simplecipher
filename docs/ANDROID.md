# Android App — SimpleCipher

> **Audience:** Everyone — from first-time users choosing an APK, to developers building from source, to security researchers auditing the trust boundaries between Java and native code.

## What is this?

SimpleCipher is a private chat app. Two people connect directly — no server, no account, no sign-up. Everything is encrypted end-to-end. When the session ends, the keys are gone. Nothing is stored to disk.

The Android app does exactly what the desktop version does, with a touch interface. It is the easiest way to use SimpleCipher — but it carries slightly higher risk than the command-line version on a clean Windows or Linux machine. Android's garbage collector can leave traces of keys and messages in memory that cannot be wiped on demand, and the OS itself may cache data in ways the app cannot fully control. The desktop CLI wipes every byte deterministically. See [Android vs desktop security comparison](#android-vs-desktop-security-comparison) for details.

## Two versions

There are two APKs to choose from. Both provide the same encryption. The only difference is how you verify the other person's identity.

| | Minimal | Full |
|---|---|---|
| **Size** | ~154 KB | ~854 KB |
| **Permissions** | Internet only | Internet + Camera (optional) |
| **Identity verification** | Safety code (read aloud) or type fingerprint | Safety code, type fingerprint, or scan QR code |
| **Dependencies** | None (just the C crypto library) | ZXing (QR code library, Apache 2.0) |
| **Best for** | Maximum trust — zero third-party code, zero extra permissions | Convenience — scan a QR code instead of typing |

**If you're unsure, start with minimal.** You can always switch later. The encryption is identical.

## How verification works

When you connect to someone, how do you know it's really them and not someone intercepting the connection? SimpleCipher gives you two ways to check.

```
  Method 1: Safety code             Method 2: Fingerprint
  (no preparation needed)           (exchange before connecting)

  ┌──────────────────────┐          ┌──────────────────────┐
  │ Open app             │          │ Open app             │
  │ Enter host/port      │          │ Tap "Fingerprint"    │
  │ Tap Start            │          │ Show QR / share code │
  └──────────┬───────────┘          │ Scan or type peer's  │
             │                      │ Tap Start            │
             ▼                      └──────────┬───────────┘
  ┌──────────────────────┐                     │
  │ Handshake            │◄────────────────────┘
  │ (automatic)          │
  └──────────┬───────────┘
             │
      ┌──────┴──────┐
      │              │
      ▼              ▼
  fingerprint     no fingerprint
  was scanned     was scanned
      │              │
      ▼              ▼
  ┌────────────┐ ┌─────────────┐
  │ Auto-check │ │ Show safety │
  │ Match? ──► │ │ code        │
  │ Go to chat │ │ Compare it  │
  └────────────┘ │ Type it in  │
                 └─────────────┘
```

### Method 1: Safety code (both versions)

After connecting, both sides see the same short code (like `A3F2-91BC`). Call your peer — video or voice — and read the code out loud. If it matches, type it in to confirm. If it doesn't match, someone is intercepting. Disconnect immediately.

**Strength:** 32 bits of entropy. The commitment scheme prevents an attacker from brute-forcing a match, so 32 bits is sufficient for interactive verification.

**When to use:** When you can make a call at connection time but haven't prepared anything in advance.

### Method 2: Fingerprint exchange (both versions)

Before connecting, both sides generate a fingerprint — a 16-character code like `58A4-0798-FE8A-4026`. Share this with your peer however you like: write it on paper, send it in a message, show it as a QR code. After the handshake, the app verifies it automatically.

**Strength:** 64 bits of entropy. Cryptographic verification — no human comparison, no "it looks close enough" mistakes.

**When to use:** When you can share a code in advance but might not be able to call at connection time.

**How to exchange fingerprints:**

*In person:*
1. Both open the app and tap "Fingerprint verification"
2. Each person shows their screen (or a printout) to the other
3. Full version: scan the QR code. Minimal version: type the 16-character code
4. Tap "Start" — the handshake verifies the fingerprint automatically

*Over a video call:*
1. Both open the app and tap "Fingerprint verification"
2. Alice holds her phone to the webcam — Bob scans or writes down the code
3. Bob holds his phone to the webcam — Alice scans or writes down the code
4. Both tap "Start"

*On paper (one-time use):*
1. Generate a fingerprint in the app
2. Write it down or print a QR code (any QR generator works)
3. Give the paper to your peer when you meet
4. When ready to chat, both enter the other's fingerprint and connect

### Why fingerprints are safe to share

A fingerprint is derived from a public key — the same key that's exchanged openly during the handshake. There is zero secret information in a fingerprint. If someone finds your printed QR code or reads your fingerprint, they gain nothing. They cannot forge a key that produces the same fingerprint.

Fingerprints are ephemeral. They change every session. A printed code works exactly once — for the session it was generated in.

### What if you skip verification?

The chat is still encrypted. But without verification, you can't be sure who you're talking to. An attacker sitting between you could intercept and read everything. Verification is how you catch them.

## Architecture

```
┌───────────────────────────────────────────┐
│ Java (UI)                                 │
│ ┌──────────────┐ ┌──────────────┐         │
│ │ MainActivity │ │ ChatActivity │         │
│ │  (connect)   │ │ (SAS + chat) │         │
│ └──────┬───────┘ └──────┬───────┘         │
│        │                │                 │
│        │  NativeCallback (interface)      │
│        │       ▲                          │
│        │       │  callbacks on UI thread  │
├────────┼───────┼──────────────────────────┤
│ C (Native, via JNI)                       │
│        │       │                          │
│        ▼       │                          │
│ ┌──────────────┴────────────────┐         │
│ │ Single native thread          │         │
│ │ ┌──────────┐  ┌─────────────┐ │         │
│ │ │ protocol │  │   crypto    │ │         │
│ │ │ network  │  │   ratchet   │ │         │
│ │ └──────────┘  └─────────────┘ │         │
│ └───────────────────────────────┘         │
│        ▲                                  │
│        │  command pipe (atomic writes)    │
│ nativePostCommand(cmd, payload)           │
│ nativeStop() — out-of-band forced quit    │
└───────────────────────────────────────────┘
```

**Why a single native thread?** All crypto, session, and socket state lives on one POSIX thread. Java communicates through a pipe. No mutexes needed for the protocol itself, no possibility of nonce reuse. Two threads reading the same key/nonce pair breaks XChaCha20-Poly1305 confidentiality completely — this architecture makes that structurally impossible. A small number of lifecycle/control globals (pipe fd, listen socket, session-active flag, generation counter) are shared between the JNI calling thread and the session thread using C11 atomics. These carry no crypto material.

## Security measures

### What the app does

| Measure | What it prevents |
|---------|-----------------|
| Screenshot blocking (`FLAG_SECURE`) | Screenshots and screen recording of the chat and verification screens |
| Overlay blocking (`HIDE_OVERLAY_WINDOWS`) | Other apps drawing on top of the screen to read your safety code |
| Custom keyboard (`SimpleKeyboard`) | Keystroke logging by third-party keyboards — covers all inputs: host, port, fingerprint (connect screen) and SAS, chat (chat screen). The system keyboard is never shown. |
| No keyboard learning (`IME_FLAG_NO_PERSONALIZED_LEARNING`) | System keyboard caching what you type (defence in depth, all inputs) |
| Session kill on background (`onStop` → `nativeStop()`) | Keys sitting in memory while the app is not visible. Uses out-of-band forced teardown (socket shutdown + pipe close + POLLHUP detection), not the command pipe, so quit cannot be blocked by network backpressure. |
| Widget clearing on pause (`onPause`) | Plaintext lingering in UI text fields |
| Native key wiping (`crypto_wipe`) | Every key and secret is zeroed in C on every exit path |
| No persistent storage | Nothing written to disk — no databases, no saved keys, no logs |
| Anti-debugging (`PR_SET_DUMPABLE=0`) | Memory dumping of crypto keys by a debugger or compromised app |
| No core dumps (`RLIMIT_CORE=0`) | Crash dumps writing key material to disk |
| Constant-time comparison | Timing attacks on fingerprint verification |

### What the app cannot guarantee

The Android app runs on the JVM. Java Strings are immutable and garbage-collected — they cannot be reliably zeroed. A message or key that passed through a Java String may linger in heap memory until the GC reclaims it.

The native C layer wipes everything it touches. But at the Java-to-native boundary, String objects exist briefly outside our control.

**For the strongest memory guarantees, use the desktop CLI or TUI.** The Android app is convenient but inherently weaker than the desktop builds due to JVM memory management.

### SOCKS5 / Tor support

The Android app supports SOCKS5 proxies in connect mode. Enter the proxy address (e.g. `127.0.0.1:9050`) in the "SOCKS5 proxy" field on the connect screen. This enables Tor via [Orbot](https://guardianproject.info/apps/org.torproject.android/) — neither side learns the other's IP address.

**Setup:**
1. Install Orbot from F-Droid or Google Play
2. Start Orbot and wait for "Connected"
3. In SimpleCipher, enter the peer's `.onion` address as the host
4. Enter `127.0.0.1:9050` as the SOCKS5 proxy
5. Tap Start

**Limitation:** SOCKS5 is connect-mode only. To accept incoming connections anonymously on Android, you would need to configure a Tor onion service, which requires root or a separate Tor daemon — use the desktop CLI for this.

For a complete guide to high-risk deployment with Tor (including onion services), see [High-Risk Deployment](DEPLOYMENT.md).

### Android vs desktop security comparison

| Property | Desktop (CLI/TUI) | Android |
|----------|-------------------|---------|
| Key wiping | Deterministic (`crypto_wipe` on every buffer) | Deterministic in C; best-effort in Java (GC) |
| Keyboard safety | Terminal handles input directly | Custom keyboard bypasses system IME |
| Screenshot protection | Not applicable (terminal) | `FLAG_SECURE` blocks screenshots |
| Memory locking | `mlockall` prevents swap-to-disk | Not available on Android |
| Seccomp sandboxing | Enabled (Linux only) | Not available on Android |
| Binary size | ~80 KB, zero dependencies | Minimal: ~154 KB; Full: ~854 KB |

### If security is your top priority

Use the desktop CLI on a hardened OS. For detailed platform recommendations — from Tails and Qubes to GrapheneOS — see [Choosing your platform](../README.md#choosing-your-platform) in the main README.

## Building

```bash
# Minimal flavor (no QR, no camera, ~154 KB)
cd android && ./gradlew assembleMinimalDebug
cd android && ./gradlew assembleMinimalRelease

# Full flavor (QR display + scanning, ~854 KB)
cd android && ./gradlew assembleFullDebug
cd android && ./gradlew assembleFullRelease

# Both flavors
cd android && ./gradlew assembleDebug
cd android && ./gradlew assembleRelease
```

**Requirements:**
- Android Studio or standalone Gradle
- NDK 28.0.13004108 (specified in `app/build.gradle`)
- SDK 35 (compile), min SDK 28 (Android 9+)
- CMake for NDK builds

**Release ABIs:** `arm64-v8a`, `armeabi-v7a` (covers ~99% of Android devices). CI adds `x86_64` for emulator testing.

**Hardening flags (native):** `-std=c23 -Os -flto -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fvisibility=hidden` with full RELRO and no lazy binding. Only JNI entry points are exported (via `jni_exports.map`).

## Permissions

### Minimal flavor

| Permission | Purpose |
|------------|---------|
| `INTERNET` | TCP connection to peer |
| `HIDE_OVERLAY_WINDOWS` | Blocks screen-overlay attacks (not a user-visible permission) |

No camera, no storage, no contacts, no location, no microphone.

### Full flavor

| Permission | Purpose | When |
|------------|---------|------|
| `INTERNET` | TCP connection to peer | Always |
| `HIDE_OVERLAY_WINDOWS` | Blocks screen-overlay attacks (not a user-visible permission) | Always |
| `CAMERA` | QR code scanning | Only when you tap "Scan peer fingerprint" — runtime request, can be denied |

No storage, contacts, location, microphone, or background permissions in either flavor. The app does nothing in the background.

## Dependencies

### Minimal flavor

| Dependency | Purpose | License |
|------------|---------|---------|
| Monocypher (vendored C) | All cryptography | BSD-2-Clause / CC0 |

No third-party Java dependencies. The entire app is the C protocol code + a thin Java UI.

### Full flavor

| Dependency | Purpose | License |
|------------|---------|---------|
| Monocypher (vendored C) | All cryptography | BSD-2-Clause / CC0 |
| ZXing core | QR code generation | Apache 2.0 |
| ZXing Android embedded | QR code scanning with camera | Apache 2.0 |

No Google Play Services dependency. Works on all Android devices including degoogled phones (LineageOS, GrapheneOS, etc.).

## File map

```
android/app/src/
├── main/                              Shared code (both flavors)
│   ├── java/com/example/simplecipher/
│   │   ├── MainActivity.java          Connect/listen screen, fingerprint panel
│   │   ├── ChatActivity.java          SAS verification, chat, auto-verify
│   │   ├── NativeCallback.java        Java <-> native callback interface
│   │   ├── SimpleKeyboard.java        Custom keyboard (HEX + QWERTY)
│   │   └── QrHelper.java             Interface for QR operations
│   ├── c/
│   │   ├── jni_bridge.c              Single-threaded native session layer
│   │   ├── jni_exports.map           JNI symbol visibility
│   │   └── CMakeLists.txt            NDK build config
│   ├── res/layout/
│   │   ├── activity_main.xml         Connect screen layout
│   │   └── activity_chat.xml         Chat screen layout
│   └── AndroidManifest.xml           Shared manifest (INTERNET only)
├── full/                              Full flavor additions
│   ├── java/com/example/simplecipher/
│   │   └── QrHelperImpl.java         ZXing QR generation + scanning
│   └── AndroidManifest.xml           Adds CAMERA permission
└── minimal/                           Minimal flavor additions
    └── java/com/example/simplecipher/
        └── QrHelperImpl.java          No-op stub (no QR support)
```
