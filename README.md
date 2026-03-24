# SimpleCipher

[![CI](https://github.com/robinvanemden/simplecipher/actions/workflows/ci.yml/badge.svg)](https://github.com/robinvanemden/simplecipher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Private chat between two people. No server. No account. No trace.

Run the program, compare a short code over the phone to make sure nobody's listening in, and start talking. Everything is encrypted end-to-end. When the session ends, the keys are gone — even if someone recorded the entire conversation, they cannot decrypt it after the fact. Nothing is stored to disk. No sign-up required.

SimpleCipher is a single tiny binary (~80 KB) with zero dependencies. The protocol is implemented in a handful of focused C modules, designed to be audited in an afternoon — built for privacy and for teaching.

**Step 1 — Alice starts listening:**

```
$ simplecipher listen

  Listening on port 7777
  Tell your peer to run:
    simplecipher connect 192.168.1.208
  Your fingerprint: D629-4DB6-9B8C-2CE1
  Waiting for connection...
```

**Step 2 — Bob connects using Alice's IP:**

```
$ simplecipher connect 192.168.1.208
```

**Step 3 — Both see the same safety code:**

```
  Safety code:  D629-4DB6          (both screens show this)
```

They call each other on the phone (or compare in person): *"I see D629-4DB6 — same for you?" "Yes."*

Both type the code to confirm:

```
  Confirm: D6294DB6
  Secure session active. Ctrl+C to quit.
```

**Step 4 — They chat. Everything is encrypted.**

```
  > hey, is this safe?
  [12:01:03] peer: yes — keys are ephemeral, wiped on exit
```

**Step 5 — Either side presses Ctrl+C. Keys are wiped. Nothing is stored.**

**Deep dives:** [Protocol and Security](docs/PROTOCOL.md) &#183; [Platform Hardening](docs/HARDENING.md) &#183; [Building and Development](docs/BUILDING.md) &#183; [Security Policy](SECURITY.md)

## Download

Grab a binary from the [latest release](https://github.com/robinvanemden/simplecipher/releases/latest) and run it. Nothing to install.

| Platform | Download | Notes |
|----------|----------|-------|
| **Linux** (most PCs/servers) | [simplecipher-linux-x86_64](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-linux-x86_64) | ~87 KB |
| **Linux** (Raspberry Pi, ARM) | [simplecipher-linux-aarch64](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-linux-aarch64) | ~91 KB |
| **Windows** (most PCs) | [simplecipher-win-x86_64.exe](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-win-x86_64.exe) | ~65 KB |
| **Windows** (ARM laptops) | [simplecipher-win-aarch64.exe](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-win-aarch64.exe) | ~58 KB |
| **Android** | [simplecipher-android.apk](https://github.com/robinvanemden/simplecipher/releases/latest/download/simplecipher-android.apk) | ~164 KB |

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

**What to do:** Call your peer (or talk in person) and read the code out loud. If both sides see the same code, type it in to confirm. If the codes don't match, someone is intercepting your connection — press Ctrl+C immediately.

**Why this matters:** The safety code is how you know you're actually talking to your friend and not to someone pretending to be them. Without this check, an attacker sitting between you could read everything. This is the single most important step — don't skip it.

## FAQ

**Can someone read my messages?**
Not if you compare the safety code. The encryption uses the same industry-standard algorithms as Signal and WhatsApp (X25519, XChaCha20-Poly1305). The code has been tested with 605 automated tests, formally verified with CBMC, and the crypto library ([Monocypher](https://monocypher.org/)) has been [professionally audited](https://monocypher.org/quality-assurance/audit). That said, SimpleCipher itself has not been formally audited as a complete system — use your judgment.

**Can someone intercept the connection?**
They can try, but the safety code comparison stops them. Both sides lock in their keys before revealing them, then derive a code that must match. If it matches, no one is in the middle. If you skip the comparison, all bets are off.

**What happens if I lose connection?**
The session is gone. Keys exist only in memory. Reconnect and start fresh — you'll get a new code.

**Why not just use Signal?**
Signal requires a phone number, an account, and a central server that knows who talks to whom. SimpleCipher has none of that. Nothing is stored, no sign-up needed. Use Signal when you need persistent contacts. Use SimpleCipher when leaving no trace matters more.

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
