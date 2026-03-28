# High-Risk Deployment Guide — SimpleCipher

> **Audience:** People who need SimpleCipher to work under active surveillance, device seizure risk, or network monitoring. If your safety depends on this tool, read this page before using it.

## The short version

Use SimpleCipher on **Tails** (USB, amnesic) or a **hardened Linux** desktop, over **[Tor](GLOSSARY.md#tor)**, with **pre-shared [fingerprint](GLOSSARY.md#fingerprint)s** on paper. Do not use Android if your threat model includes device seizure or memory forensics.

## Security layers at a glance

Every layer addresses a different class of threat. Skip one and you have a gap.

```
+----------------------------------------------------+
|          Operational Security (you)                 |
|  Clean device, FDE, no logs, session discipline     |
|  Threat: forensics, metadata leaks, human error     |
|  High-risk: Tails USB, paper fingerprints, no tmux  |
+----------------------------------------------------+
|          Identity Verification                      |
|  SAS code comparison + fingerprint pre-exchange     |
|  Threat: man-in-the-middle during handshake         |
|  High-risk: paper fingerprints exchanged in person  |
+----------------------------------------------------+
|          Network Layer                              |
|  Direct / Tor (.onion) / SOCKS5 proxy              |
|  Threat: IP exposure, traffic correlation           |
|  High-risk: Tor onion service + cover traffic       |
+----------------------------------------------------+
|          Operating System                           |
|  Tails > Qubes > hardened Linux > stock Linux       |
|  Threat: disk forensics, memory dumps, swap leaks   |
|  High-risk: Tails (amnesic, routes all through Tor) |
+----------------------------------------------------+
|          SimpleCipher Runtime                       |
|  Ephemeral keys, seccomp, mlockall, crypto_wipe     |
|  Threat: key extraction, syscall abuse, memory leak |
|  High-risk: build with CIPHER_HARDEN (default)      |
+----------------------------------------------------+
```

Each layer maps to a section below: OS ([section 1](#1-operating-system)), network ([section 2](#2-network-use-tor)), identity ([section 3](#3-identity-verification-pre-shared-fingerprints)), operational security ([section 4](#4-operational-security-checklist)), and runtime limits ([section 5](#5-what-simplecipher-cannot-protect-against)).

## Recommended setup

### 1. Operating system

| Choice | Why | Trade-off |
|--------|-----|-----------|
| **Tails** (best) | Boots from USB, writes nothing to disk, routes everything through Tor, shuts down clean | Must reboot to use; no persistent state by design |
| **Qubes OS** | Each app in its own VM; a compromised browser cannot touch your chat | More complex setup; needs compatible hardware |
| **Hardened Linux** (Debian/Fedora + FDE) | `mlockall` + [seccomp](PROTOCOL.md#seccomp) enabled; full-disk encryption protects at rest | Swap and terminal scrollback may retain traces |

Do **not** use Windows for high-risk use — no `mlockall`, no seccomp, no memory locking.

Do **not** use Android for high-risk use — JVM garbage collection leaves keys and plaintext in memory that cannot be wiped deterministically. See [Android vs desktop comparison](ANDROID.md#android-vs-desktop-security-comparison).

### 2. Network: use Tor

SimpleCipher encrypts message content, but your IP address is visible to the peer and to anyone watching the network. For anonymity, route through Tor.

**Connecting through Tor (easy):**

```bash
# Install Tor (Tails has it built in)
sudo apt install tor

# Connect through Tor's SOCKS5 proxy (interactive — keeps address out of argv)
simplecipher connect --socks5 127.0.0.1:9050
#   Host: <peer-onion-address>
```

**Note:** The `--socks5` flag itself appears in `/proc/cmdline` and shell history. This reveals that you're using a [SOCKS5](GLOSSARY.md#socks5) proxy but not who you're connecting to (the host is entered interactively). On Tails this is not a concern — the amnesic OS discards everything on shutdown.

**Listening as a Tor onion service:**

```bash
# 1. Add to /etc/tor/torrc:
HiddenServiceDir /var/lib/tor/simplecipher/
HiddenServicePort 7777 127.0.0.1:7777

# 2. Restart Tor
sudo systemctl restart tor

# 3. Get your .onion address
cat /var/lib/tor/simplecipher/hostname

# 4. Listen with cover traffic — Tor routes incoming connections
simplecipher listen --cover-traffic
```

Your peer connects to the `.onion` address via `--socks5` (which enables [cover traffic](GLOSSARY.md#cover-traffic) automatically). The `--cover-traffic` flag on the listener ensures both sides send dummy frames, defeating timing correlation from either direction.

### 3. Identity verification: pre-shared fingerprints

The strongest verification method is **fingerprints exchanged on paper** when you meet in person. This eliminates the need for a phone call at connection time and provides 64-bit cryptographic verification (vs 32-bit for the [safety code](PROTOCOL.md#sas)).

**Setup (one-time, in person):**

1. Both run `simplecipher keygen mykey.dat` — choose a passphrase you can remember
2. Write down each other's fingerprint on paper (or print a QR code) and exchange
3. Store the paper securely — it has no secret value (derived from a public key), but it identifies your peer across sessions
4. Store the key file (`mykey.dat`) on a USB stick or encrypted volume — it is protected by the passphrase (something you have + something you know)

**Each session:**

```bash
# Listener (loads identity key, also verifies connector's fingerprint)
simplecipher listen --identity mykey.dat --peer-fingerprint YYYY-YYYY-YYYY-YYYY --trust-fingerprint

# Connector (loads identity key, uses the paper fingerprint — interactive to keep address off argv)
simplecipher connect --identity mykey.dat --peer-fingerprint XXXX-XXXX-XXXX-XXXX --trust-fingerprint
#   Host: <address>
```

With `--trust-fingerprint`, the 64-bit fingerprint verification is treated as sufficient — the interactive SAS screen is skipped and the session goes straight to encrypted chat. This is the ideal mode for pre-shared paper fingerprints: no phone call needed at session time.

Without `--trust-fingerprint`, the fingerprint is verified first, then the SAS screen appears as a second layer (defence in depth). If the fingerprint doesn't match, the connection is aborted immediately — someone is intercepting.

**Important:** With `keygen`, fingerprints are stable — the same key file always produces the same fingerprint, so the paper fingerprint works across sessions. Without `keygen`, fingerprints are [ephemeral](PROTOCOL.md#ephemeral) and change every session.

### 4. Operational security checklist

Before the session:

- [ ] Booted from Tails USB (or verified full-disk encryption is active)
- [ ] Tor is running (`systemctl status tor`)
- [ ] Terminal scrollback is minimal (Tails handles this; on Linux, reduce scrollback buffer)
- [ ] No screen recording software is running
- [ ] You have the peer's fingerprint on paper (or can make a voice/video call)

During the session:

- [ ] Verified the safety code or fingerprint matched
- [ ] Not copying messages to clipboard (clipboard is shared with other apps)
- [ ] **Not running inside tmux or screen** (their scrollback survives terminal purge — use a plain terminal window)

After the session:

- [ ] Pressed Ctrl+C to end cleanly (keys wiped, terminal purged)
- [ ] On Tails: shut down (RAM is wiped on shutdown)
- [ ] On Linux: close the terminal window (clears scrollback)

### 5. What SimpleCipher cannot protect against

Even with the setup above, these risks remain:

- **A compromised OS** — if the operating system itself is backdoored, everything is visible. Use Tails or Qubes to minimize this.
- **Physical observation** — someone looking at your screen sees the conversation. Position yourself accordingly.
- **Endpoint compromise during the session** — if an attacker has code execution on your machine while SimpleCipher is running, they can read memory. `mlockall` + seccomp reduce the attack surface but cannot prevent a kernel-level compromise.
- **The peer** — SimpleCipher protects the channel, not the endpoints. If your peer is compromised or is the adversary, encryption doesn't help.
- **Metadata** — even with Tor, the timing and frequency of your connections may be observable. Tor hides IP addresses, not usage patterns. Cover traffic (`--cover-traffic` on desktop, automatic with SOCKS5 on Android) mitigates timing correlation.
- **Traffic fingerprinting** — all messages (handshake and chat) use randomized wire padding, so there is no fixed byte count to fingerprint. However, statistical traffic analysis (packet timing, session structure) may still identify the protocol. Tor wraps everything in TLS cells, providing additional protection.
- **Connection racing** — the listener accepts the first TCP connection unconditionally. A local attacker (or any host that can reach the port) could connect before the real peer. The [SAS](PROTOCOL.md#sas) verification catches this, but only if the user actually verifies carefully. On untrusted networks, always use Tor onion services instead of direct listen.
- **Safety code verification call** — comparing the [SAS](PROTOCOL.md#sas) by phone creates a metadata trail: call records link two people at the exact time of the session. Pre-shared paper fingerprints (`--peer-fingerprint`) automate the identity check, but the SAS confirmation step still runs as defence in depth. The fingerprint eliminates the *need* for a live voice/video call, not the SAS screen itself. If a call is unavoidable, use a burner phone or introduce a time gap between the handshake and the call.
- **Terminal multiplexers** — tmux and screen maintain their own scrollback buffers in a separate process. SimpleCipher's terminal purge (`\033[3J`) cannot reach them. **Never run SimpleCipher inside tmux or screen.** Use a dedicated terminal window and close it immediately after the session.

### 6. Platform-specific notes

**Tails:**
- SimpleCipher runs without installation — download the binary to the Tails session (it's ~87 KB)
- Tor is already running; use `--socks5 127.0.0.1:9050` (cover traffic enabled automatically)
- For listening behind an onion service, add `--cover-traffic` explicitly
- Everything is wiped on shutdown — no cleanup needed
- The binary itself disappears after reboot (unless saved to persistent storage, which you should avoid)

**Qubes OS:**
- Run SimpleCipher in a disposable qube (AppVM)
- Route through `sys-whonix` for Tor — add `--cover-traffic` since transparent routing bypasses `--socks5`
- The qube is destroyed after use — clean slate every time

**Hardened Linux:**
- Build with `CIPHER_HARDEN` (release binaries have this enabled)
- Verify: `./simplecipher --help` shows "Hardening (active in this build)"
- Set `ulimit -l unlimited` before running (allows `mlockall`)
- Use full-disk encryption (LUKS) and encrypted swap

**FreeBSD / OpenBSD:**
- Both have kernel-level sandboxing (Capsicum / pledge) integrated and CI-verified
- OpenBSD is the smallest attack surface of any general-purpose OS
- FreeBSD has Capsicum + robust POSIX; both are strong choices for a dedicated chat terminal
