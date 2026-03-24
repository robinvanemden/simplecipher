# SimpleCipher

[![CI](https://github.com/robinvanemden/simplecipher/actions/workflows/ci.yml/badge.svg)](https://github.com/robinvanemden/simplecipher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Private chat between two people. No server. No account. Nothing stored to disk.

Run the program, compare a short code over the phone to make sure nobody's listening in, and start talking. Everything is encrypted end-to-end. When the session ends, the keys are gone — even if someone recorded the entire conversation, they cannot decrypt it after the fact. Nothing is stored to disk. No sign-up required.

> **Security notice:** SimpleCipher has not been independently audited. Do not rely on it in situations where a security failure could put anyone at risk without first commissioning a professional review of the code and your deployment environment.

SimpleCipher is a single tiny binary (~80 KB) with zero dependencies. The protocol is implemented in a handful of focused C modules, designed to be audited in an afternoon — built for privacy and for teaching.

**Step 1 — Alice starts listening:**

```
$ simplecipher listen

  Listening on port 7777
  Tell your peer to run:
    simplecipher connect 192.168.1.208
  Your fingerprint: 58A4-0798-FE8A-4026
  Waiting for connection...
```

**Step 2 — Bob connects (interactive — keeps the address out of shell history):**

```
$ simplecipher connect
  Host: 192.168.1.208
  Port [7777]:
```

**Step 3 — Both see the same safety code:**

```
  Safety code:  58A4-0798          (both screens show this)
```

Alice and Bob compare the code over a video call: *"I see 58A4-0798 — same for you?" "Yes."*

Both type the code to confirm:

```
  Confirm: 58A40798
  Secure session active. Ctrl+C to quit.
```

**Step 4 — They chat. Everything is encrypted.**

```
  > hey, is this safe?
  [12:01:03] peer: yes — keys are ephemeral, wiped on exit
```

**Step 5 — Either side presses Ctrl+C. Keys are wiped. Nothing is stored.**

**Deep dives:** [Protocol and Security](docs/PROTOCOL.md) &#183; [Platform Hardening](docs/HARDENING.md) &#183; [Building and Development](docs/BUILDING.md) &#183; [Android App](docs/ANDROID.md) &#183; [Design Boundaries](docs/DESIGN_BOUNDARIES.md) &#183; [Assurance Map](docs/ASSURANCE_MAP.md) &#183; [Security Policy](SECURITY.md)

## Download

Grab a binary from the [latest release](https://github.com/robinvanemden/simplecipher/releases/latest) and run it. Nothing to install.

| Platform | Download | Notes |
|----------|----------|-------|
| **Linux** (most PCs/servers) | [simplecipher-linux-x86_64](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-linux-x86_64) | ~87 KB |
| **Linux** (Raspberry Pi, ARM) | [simplecipher-linux-aarch64](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-linux-aarch64) | ~91 KB |
| **Windows** (most PCs) | [simplecipher-win-x86_64.exe](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-win-x86_64.exe) | ~65 KB |
| **Windows** (ARM laptops) | [simplecipher-win-aarch64.exe](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-win-aarch64.exe) | ~58 KB |
| **Android** (minimal) | [simplecipher-minimal.apk](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-minimal.apk) | ~154 KB, no extra permissions |
| **Android** (full) | [simplecipher-full.apk](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-full.apk) | ~854 KB, adds QR scanning |

All desktop binaries are fully static with zero runtime dependencies. Both Android APKs use the same encryption — the difference is QR code support. See [Android App](docs/ANDROID.md) for details.

## Quick start

The easiest way to chat across different networks is with [Tailscale](https://tailscale.com/) (free for personal use, 2-minute setup). Tailscale creates a WireGuard mesh so your devices can reach each other. SimpleCipher encrypts on top of that — ephemeral keys, SAS verification, and forward secrecy that Tailscale alone does not provide.

```bash
# Both devices: install Tailscale (one-time)
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up

# Person A: listen for a connection
simplecipher listen

# Person B: connect (interactive prompt — address stays out of shell history)
simplecipher connect
```

On the same Wi-Fi or LAN, skip Tailscale entirely — just use the local IP:

```bash
# Person A
simplecipher listen

# Person B (interactive — or: simplecipher connect 192.168.1.42)
simplecipher connect
```

### Other ways to connect

SimpleCipher encrypts your messages, but your IP address is still visible to the network. The transport you choose determines who can see that you're connecting:

| Method | When to use | Who sees your IP |
|--------|-------------|------------------|
| **LAN / Wi-Fi** | Same network | Nobody outside the network |
| **Tailscale** (easiest) | Different networks, quick setup | Tailscale's coordination server sees both endpoints |
| **WireGuard** | Manual VPN tunnel between devices | Your VPN peer only |
| **Port forwarding** | Forward port 7777 on your router | Anyone who knows the IP can attempt a connection |
| **Tor** | Anonymity matters | Neither side learns the other's IP; network observers see Tor traffic but not the destination |

**If you need anonymity** — not just encryption — use Tor:

```bash
# Connecting through Tor (easy — just wrap with --socks5):
simplecipher connect --socks5 127.0.0.1:9050 <onion-address>

# Listening as a Tor onion service (requires onion service setup):
# 1. Add to /etc/tor/torrc:
#      HiddenServiceDir /var/lib/tor/simplecipher/
#      HiddenServicePort 7777 127.0.0.1:7777
# 2. Restart Tor:  sudo systemctl restart tor
# 3. Get your .onion address:  cat /var/lib/tor/simplecipher/hostname
# 4. Listen normally:  simplecipher listen
# Your peer connects to the .onion address via --socks5.
```

Note: `torsocks` only works for **outbound** connections (connect). To accept incoming connections anonymously, you must configure a Tor onion service as shown above. See the [Tor onion services documentation](https://community.torproject.org/onion-services/setup/) for details.

### Options

```bash
# Specify a custom port (default: 7777)
simplecipher listen 9000
simplecipher connect 100.x.y.z 9000

# Split-pane terminal UI with scrolling messages and fixed input line
simplecipher --tui listen
simplecipher --tui connect 100.x.y.z

# Connect through a SOCKS5 proxy (e.g. Tor on 127.0.0.1:9050)
simplecipher connect --socks5 127.0.0.1:9050 <onion-address>

# Interactive mode: omit host to avoid leaking it to shell history
simplecipher connect
#   Host: 100.70.179.3
#   Port [7777]:

# Verify peer identity with a pre-shared fingerprint
simplecipher connect --peer-fingerprint A3F2-91BC-D4E5-F678 100.x.y.z
```

TUI mode works on Linux, macOS, and Windows 10+. No dependencies — pure ANSI escape sequences.

**SOCKS5 proxy** (`--socks5`): tunnels the connection through any SOCKS5 proxy. Essential for Tor — the proxy resolves DNS, so `.onion` addresses work and no DNS queries leak from your machine.

**Interactive connect**: running `simplecipher connect` without a host prompts for it on stdin. The target address never appears in `argv`, shell history, or `/proc/*/cmdline`.

**Peer fingerprint** (`--peer-fingerprint`): the listener's fingerprint is shown on the listen screen *before* any connection is made, so it can be shared while waiting for a peer. The connector passes it as a flag. After the handshake, the peer's public key is hashed and compared — mismatch aborts the connection. This is optional additional verification on top of the SAS code, useful when you can pre-share a fingerprint but can't make a phone call.

On Android, the same flow happens through the app UI: choose Listen or Connect, enter the host/port, verify the safety code, and chat.

### Safety code verification

After connecting, both sides see the same safety code:

```
+------------------------------------------+
|  COMPARE THIS CODE WITH YOUR PEER        |
|  before typing anything                  |
+------------------------------------------+
  Safety code:  A3F2-91BC

Type the full code to confirm:
```

**What to do:** Compare the code with your peer through a channel you already trust. Read it out loud and confirm both sides see the same code. Then type it in. If the codes don't match, someone is intercepting — press Ctrl+C immediately.

**How to compare (best to acceptable):**

| Method | Why |
|--------|-----|
| **Paper with fingerprint** (best) | Exchange `--peer-fingerprint` codes on paper when you meet. Paper can't be hacked — no network, no device, no interception. Verify automatically on every future session. |
| **Video call** | You see and hear the person — very hard to fake in real time |
| **Voice call** | You recognize their voice — good if you know them well |
| **Pre-shared fingerprint via Signal/secure chat** | Shared digitally in advance — only as secure as that channel |
| **Text message** | Weakest — an attacker who controls the network might also control SMS. Better than nothing. |

**Why this matters:** The safety code is how you know you're actually talking to your friend and not to someone pretending to be them. Without this check, an attacker sitting between you could read everything. This is the single most important step — don't skip it.

## Choosing your platform

SimpleCipher runs on Linux, Windows, and Android. The encryption is identical everywhere — the same C code, the same protocol. What differs is how well the operating system protects your keys while they're in memory.

### Quick comparison

| Platform | Security | Ease of use | Best for |
|----------|----------|-------------|----------|
| **Desktop CLI/TUI** on a hardened OS | Strongest | Requires terminal | When minimizing forensic traces matters most |
| **Desktop CLI/TUI** on a standard OS | Strong | Requires terminal | Everyday private conversations |
| **Android app** (minimal) | Good | Easiest | Quick, convenient chats on the go |
| **Android app** (full) | Good | Easiest + QR scanning | Same, with camera-based verification |

The desktop builds wipe every byte of key material deterministically. The Android app runs on the JVM, where the garbage collector can leave traces of keys and messages in memory that cannot be wiped on demand. See [Android App](docs/ANDROID.md) for a detailed comparison.

### Hardening your setup

SimpleCipher encrypts your conversation. The operating system protects everything around it — memory, swap, disk, network metadata. A hardened OS closes gaps that SimpleCipher alone cannot.

**Desktop (strongest to practical):**

| OS | Why | Good to know |
|----|-----|--------------|
| [Tails](https://tails.net/) | Amnesic — runs from USB, writes nothing to disk, routes everything through Tor | Boots fresh every time. Nothing survives a reboot — not even by accident. Use with `--socks5 127.0.0.1:9050` for full anonymity. |
| [Qubes OS](https://www.qubes-os.org/) | Compartmentalized — each app runs in its own virtual machine | A compromised browser in one VM cannot touch your chat in another. Use a disposable qube for one-time sessions. |
| [OpenBSD](https://www.openbsd.org/) | Smallest attack surface of any general-purpose OS, `pledge`/`unveil` sandboxing | Secure by default. Fewer things running means fewer things to exploit. **Note:** OpenBSD builds compile and are source-reviewed but have no CI runner — tested manually only. See [Assurance Map](docs/ASSURANCE_MAP.md). |
| Any Linux with full-disk encryption | `mlockall` + seccomp enabled, encrypted swap | A fresh Debian, Fedora, or Arch install with no unnecessary services. Encrypt the disk so a stolen laptop reveals nothing. |
| Windows 10/11 with BitLocker | Encrypted disk, standard protections | Better than an unencrypted machine. Less hardening available than Linux. |

**Android:**

| OS | Why |
|----|-----|
| [GrapheneOS](https://grapheneos.org/) | Hardened Android — no Google services, verified boot, improved sandboxing. SimpleCipher's minimal flavor runs without any Google dependencies. |
| Stock Android | Standard security. The app's built-in protections (screenshot blocking, custom keyboard, session kill on background) help, but the OS is not designed for high-security use. |

**If you're just getting started:** a standard Linux or Windows machine with full-disk encryption is a solid baseline. If your threat model demands more, move up the table.

## FAQ

**Can someone read my messages?**
Not if you compare the safety code. The encryption uses the same industry-standard algorithms as Signal and WhatsApp (X25519, XChaCha20-Poly1305). The code has been tested with 694 automated tests, formally verified with CBMC, and the crypto library ([Monocypher](https://monocypher.org/)) has been [professionally audited](https://monocypher.org/quality-assurance/audit). That said, SimpleCipher itself has not been independently audited as a complete system. If your safety depends on this tool, commission a professional audit first.

**Can someone intercept the connection?**
They can try, but the safety code comparison stops them. Both sides lock in their keys before revealing them, then derive a code that must match. If it matches, no one is in the middle. If you skip the comparison, all bets are off.

**What happens if I lose connection?**
The session is gone. Keys exist only in memory. Reconnect and start fresh — you'll get a new code.

**Why not just use Signal?**
Signal requires a phone number, an account, and a central server that knows who talks to whom. SimpleCipher has none of that. Nothing is stored, no sign-up needed. Use Signal when you need persistent contacts. Use SimpleCipher when storing nothing to disk matters more.

**Can I use this over the internet without a VPN?**
Yes, if one side has a reachable IP (port forwarding, cloud server, etc.). See [Quick start](#quick-start) for options. For anonymity, use [Tor](#other-ways-to-connect).

**Why is it so small?**
No dependencies. No TLS library, no HTTP stack, no JSON parser. Just a handful of C files compiled into one static binary.

## Verifying release binaries

Every release binary has a [Sigstore](https://www.sigstore.dev/) build provenance attestation. This proves the binary was built by this repository's CI workflow — not by an unrelated third party.

**What attestation proves:** the binary was produced by a specific GitHub Actions workflow in this repository, at a specific commit, with a specific set of inputs. The attestation is signed by Sigstore's transparency log.

**What attestation does NOT prove:** that the workflow itself is safe. If the workflow were compromised (e.g. a malicious dependency or a tampered action), the attestation would still be valid for the compromised artifact. Attestation is provenance, not a security guarantee.

```bash
# Online verification:
gh attestation verify simplecipher-linux-x86_64 --repo robinvanemden/simplecipher

# Offline verification:
gh attestation download simplecipher-linux-x86_64 --repo robinvanemden/simplecipher
gh attestation verify simplecipher-linux-x86_64 \
  --repo robinvanemden/simplecipher \
  --bundle ./simplecipher-linux-x86_64.sigstore.json
```

SHA256 checksums are also provided in `SHA256SUMS.txt` for quick integrity checks, but note that checksums alone do not prove authenticity — they are produced in the same CI job as the binaries.

## License

[MIT](LICENSE) — Monocypher is [BSD-2-Clause / CC0](lib/monocypher.h).
