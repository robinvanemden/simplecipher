# SimpleCipher

[![CI](https://github.com/robinvanemden/simplecipher/actions/workflows/ci.yml/badge.svg)](https://github.com/robinvanemden/simplecipher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Encrypted peer-to-peer chat in C. No server. No account. No dependencies.

Two people run the program, compare a short safety code over the phone, and start talking. Everything is encrypted, authenticated, and forward-secret. When the session ends, the keys are gone — even if someone recorded the entire conversation, they cannot decrypt it after the fact.

The protocol is implemented across a handful of focused C modules, designed to be audited in an afternoon. SimpleCipher is built for privacy and for teaching.

**Deep dives:** [Protocol and Security](docs/PROTOCOL.md) &#183; [Platform Hardening](docs/HARDENING.md) &#183; [Building and Development](docs/BUILDING.md) &#183; [Security Policy](SECURITY.md)

## Download

Grab a binary from the [latest release](https://github.com/robinvanemden/simplecipher/releases/latest) and run it. Nothing to install.

| Platform | Download | Size |
|----------|----------|------|
| Linux x86_64 | [simplecipher-linux-x86_64](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-linux-x86_64) | ~87 KB |
| Linux aarch64 | [simplecipher-linux-aarch64](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-linux-aarch64) | ~91 KB |
| Windows x86_64 | [simplecipher-win-x86_64.exe](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-win-x86_64.exe) | ~65 KB |
| Windows aarch64 | [simplecipher-win-aarch64.exe](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-win-aarch64.exe) | ~58 KB |
| Android (arm64 + armv7) | [simplecipher-android.apk](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-android.apk) | ~164 KB |

All desktop binaries are fully static with zero runtime dependencies.

## Quick start

The easiest way to chat across different networks is with [Tailscale](https://tailscale.com/) (free for personal use, 2-minute setup). Tailscale creates a WireGuard mesh so your devices can reach each other. SimpleCipher encrypts on top of that — ephemeral keys, SAS verification, and forward secrecy that Tailscale alone does not provide.

```bash
# Both devices: install Tailscale (one-time)
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up

# Person A: listen for a connection
simplecipher listen

# Person B: connect using Person A's Tailscale IP
simplecipher connect 100.x.y.z
```

On the same Wi-Fi or LAN, skip Tailscale entirely — just use the local IP:

```bash
# Person A
simplecipher listen

# Person B
simplecipher connect 192.168.1.42
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

Call your peer on a separate channel (phone, in person) and compare the code. If it matches, type the full code to confirm (dashes optional, case-insensitive). If it does not match, someone is intercepting — press Ctrl+C.

**The safety code comparison IS the authentication.** Skip it and a man-in-the-middle can read everything.

## FAQ

**Why not just use Signal / WhatsApp / Telegram?**
Those require accounts, phone numbers, and a central server that knows who talks to whom. SimpleCipher has no server, no accounts, and no keys stored to disk. There is no central record of who talked to whom. When the session ends, the keys are gone. The application stores no protocol state, message history, or contact list — but note that the underlying OS may retain artifacts (terminal scrollback, shell history if host/port were on the command line, swap/pagefile, OS-level logging). Use `--socks5` and the interactive connect prompt to minimize command-line exposure. Use Signal when you need persistent contacts and key continuity. Use SimpleCipher when minimal trace matters more.

**Why not just use Tailscale / WireGuard and any chat app?**
Tailscale solves connectivity (NAT traversal), not trust. SimpleCipher adds: ephemeral keys (nothing stored to disk), SAS verification (cryptographic proof of who you're talking to), and forward secrecy (keys wiped after each message). Even if the VPN layer were compromised, SimpleCipher's end-to-end encryption holds. They're complementary — use Tailscale for connectivity, SimpleCipher for trust.

**Is this secure enough for real use?**
The cryptographic primitives (X25519, XChaCha20-Poly1305, BLAKE2b) are industry-standard and provided by [Monocypher](https://monocypher.org/), which has been [audited by Cure53](https://monocypher.org/quality-assurance/audit). The protocol is split into focused modules that are simple enough to audit in an afternoon. That said, this has not been formally audited as a complete system. Use your judgment.

**Why is the binary so small?**
No runtime dependencies. No TLS library, no HTTP stack, no JSON parser, no dynamic linking. The entire program is a handful of focused C modules compiled into a single static binary. Size optimization (`-Os -flto --gc-sections`) removes everything unused.

**Can someone intercept the connection?**
A man-in-the-middle can try, but the commitment scheme and safety code verification prevent it. Both sides commit to their keys before revealing them, then derive a short authentication string (SAS) that must be compared out-of-band (phone call, in person). If the codes match, no MITM is present. If you skip the verification, all bets are off.

**What happens if I lose connection mid-chat?**
The session is gone. Keys are ephemeral and exist only in memory. Reconnect and start a new session — you'll get new keys and a new safety code.

**Can I use this over the internet without a VPN?**
Yes, if one side has a reachable IP (port forwarding, cloud server, etc.). See [Quick start](#quick-start) for options.

**Why C and not Rust / Go / Python?**
C compiles everywhere, links statically, produces tiny binaries, and has zero runtime overhead. The entire protocol fits in a small set of focused modules that can be audited, cross-compiled to 5 targets, and linked directly into Android via JNI. No package manager, no build system complexity, no garbage collector.

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
