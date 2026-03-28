# SimpleCipher

[![CI](https://github.com/robinvanemden/simplecipher/actions/workflows/ci.yml/badge.svg)](https://github.com/robinvanemden/simplecipher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Private chat between two people. No server. No account. Nothing stored to disk.

Run the program, compare a short code over the phone to make sure nobody's listening in, and start talking. Everything is [end-to-end encrypted](docs/GLOSSARY.md#end-to-end-encryption-e2ee). When the session ends, the keys are gone — even if someone recorded the entire conversation, they cannot decrypt it after the fact. No sign-up required.

> **Security notice:** SimpleCipher has not been independently audited. Do not rely on it in situations where a security failure could put anyone at risk without first commissioning a professional review of the code and your deployment environment.

> **New to cryptography?** You don't need to understand any of the technical details to use SimpleCipher — just follow the steps below. If you're curious about how it works or want to learn, the [Walkthrough](docs/WALKTHROUGH.md) explains the protocol step by step, and the [Glossary](docs/GLOSSARY.md) defines every technical term.

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
  Safety code:  9052-EF29          (both screens show this)
```

Alice and Bob compare the code over a video call: *"I see 9052-EF29 — same for you?" "Yes."*

Both type the code to confirm:

```
  Confirm: 9052EF29
  Secure session active. Ctrl+C to quit.
```

**Step 4 — They chat. Everything is encrypted.**

```
  > hey, is this safe?
  [12:01:03] peer: yes — keys are ephemeral, wiped on exit
```

**Step 5 — Either side presses Ctrl+C. Keys are wiped. Nothing is stored.**

**Learn:** [Code Walkthrough](docs/WALKTHROUGH.md) (guided tour, ~1 hour) &#183; [Protocol and Security](docs/PROTOCOL.md) (formal spec + glossary)

**Deep dives:** [Platform Hardening](docs/HARDENING.md) &#183; [Building and Development](docs/BUILDING.md) &#183; [Android App](docs/ANDROID.md) &#183; [High-Risk Deployment](docs/DEPLOYMENT.md) &#183; [Design Boundaries](docs/DESIGN_BOUNDARIES.md) &#183; [Assurance Map](docs/ASSURANCE_MAP.md) &#183; [Security Policy](SECURITY.md)

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

## Ways to use SimpleCipher

There are several ways to use SimpleCipher, from simplest to most secure.

| Method | Security | Best for | You need |
|--------|----------|----------|----------|
| [Same Wi-Fi](#same-wi-fi) | Good | Chatting with someone in the same building | Wi-Fi |
| [Tailscale](#over-the-internet-with-tailscale) | Good | Easiest way to chat across the internet | Free [Tailscale](https://tailscale.com/) account |
| [Port forwarding](#over-the-internet-with-port-forwarding) | Good | Chatting across the internet without extra software | Router access |
| [Pre-shared fingerprints](#with-pre-shared-fingerprints-paper) | Very strong | Verifying identity without a phone call | To meet in person first |
| [Pre-shared fingerprints + trust](#with-pre-shared-fingerprints--trust-fingerprint) | Very strong | Fully automatic verification, no phone call | To meet in person first |
| [Over Tor](#over-tor) | Strongest | Hiding who is talking to whom | [Tor](docs/GLOSSARY.md#tor) installed |
| [Over Tor + fingerprints](#over-tor-with-pre-shared-fingerprints) | Strongest | Maximum: anonymous + verified identity | Tor + met in person first |

All methods encrypt your conversation the same way. The difference is how you connect and how you verify each other's identity.

---

### Same Wi-Fi

**What this is.** You and your friend are both connected to the same Wi-Fi network -- at home, at the office, or in the same building. Your computers can see each other directly.

**Verification:** [Safety code](docs/GLOSSARY.md#safety-code) -- you compare a short code over the phone. Takes 10 seconds.

**Steps:**

1. You start listening. SimpleCipher shows your [IP address](docs/GLOSSARY.md#ip-address) (the number that identifies your computer on the network, like 192.168.1.42).
2. Tell your friend the IP address.
3. Your friend connects.
4. You both see a safety code. Call each other and read it out loud. If it matches, type it in.
5. Chat. Everything is encrypted.

```bash
# You: start listening
simplecipher listen

# Your friend: connect (type the IP address when prompted)
simplecipher connect
```

---

### Over the internet with Tailscale

**What this is.** [Tailscale](https://tailscale.com/) is a free service that lets your computers find each other across the internet. Think of it as a private tunnel between your devices. SimpleCipher encrypts on top of that tunnel -- [ephemeral](docs/GLOSSARY.md#ephemeral) keys, safety code verification, and [forward secrecy](docs/GLOSSARY.md#forward-secrecy) that Tailscale alone does not provide.

**Verification:** [Safety code](docs/GLOSSARY.md#safety-code) -- you compare a short code over the phone. Takes 10 seconds.

**Steps:**

1. Both you and your friend install Tailscale (one time, takes 2 minutes).
2. You start listening.
3. Your friend connects using the Tailscale IP address (it starts with `100.`).
4. Compare the safety code over a phone call.
5. Chat.

```bash
# Both devices: install Tailscale (one-time)
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up

# You: start listening
simplecipher listen

# Your friend: connect (type the Tailscale IP when prompted)
simplecipher connect
```

---

### Over the internet with port forwarding

**What this is.** One side opens a [port](docs/GLOSSARY.md#port) (a numbered doorway) on their router so the other side can connect directly over the internet. This avoids any third-party service, but you need access to your router's settings.

**Verification:** [Safety code](docs/GLOSSARY.md#safety-code) -- you compare a short code over the phone. Takes 10 seconds.

**Steps:**

1. Log into your router and forward port 7777 to your computer. (Search "[your router brand] port forwarding" for instructions.)
2. Find your public IP address by searching "what is my IP" in a web browser.
3. Start listening.
4. Send your public IP address to your friend.
5. Your friend connects.
6. Compare the safety code over a phone call.
7. Chat.

```bash
# You (after setting up port forwarding): start listening
simplecipher listen

# Your friend: connect using your public IP
simplecipher connect
```

**Note:** Anyone who knows your IP can attempt to connect while the port is open. SimpleCipher will reject anyone who does not complete the safety code verification. Close the port forwarding when you are done.

---

### With pre-shared fingerprints (paper)

**What this is.** A [fingerprint](docs/GLOSSARY.md#fingerprint) is a short code (like `A3F2-91BC-D4E5-F678`) that identifies your copy of SimpleCipher for one session. When you meet your friend in person, you each run `simplecipher listen` to see your fingerprint, write it down on paper, and hand it to each other. Later, when you chat, SimpleCipher checks the fingerprint automatically. You still confirm a safety code, but the fingerprint adds an extra layer of trust.

Think of it like exchanging secret handshakes in person, then using them later to prove who you are.

**Verification:** [Fingerprint](docs/GLOSSARY.md#fingerprint) verified first, then [safety code](docs/GLOSSARY.md#safety-code). Both layers of protection.

**Steps:**

1. When you meet in person, both run `simplecipher listen` to see your fingerprints. Write them on paper and exchange.
2. Later, when you want to chat, you start listening with your friend's fingerprint.
3. Your friend connects with your fingerprint.
4. SimpleCipher checks the fingerprints automatically. If they don't match, it stops.
5. Compare the safety code over a phone call.
6. Chat.

```bash
# You: start listening with your friend's fingerprint from the paper
simplecipher listen --peer-fingerprint B7E2-04AC-F931-8D56

# Your friend: connect with your fingerprint from the paper
simplecipher connect --peer-fingerprint A3F2-91BC-D4E5-F678
```

**Note:** Fingerprints change every session. Exchange new ones each time you meet.

---

### With pre-shared fingerprints + --trust-fingerprint

**What this is.** Same as above, but you add `--trust-fingerprint` to skip the safety code entirely. Since you exchanged fingerprints on paper in person, the fingerprint alone is enough to verify identity. No phone call needed at chat time.

The fingerprint (64-bit) is cryptographically stronger than the safety code (32-bit), so this is safe when the fingerprint was exchanged through a trusted channel like paper.

**Verification:** [Fingerprint](docs/GLOSSARY.md#fingerprint) only -- fully automatic, no phone call needed.

**Steps:**

1. Exchange fingerprints on paper when you meet in person (same as above).
2. When you want to chat, both add `--trust-fingerprint`.
3. SimpleCipher checks the fingerprints and starts the chat automatically.

```bash
# You: listen with your friend's fingerprint + trust
simplecipher listen --peer-fingerprint B7E2-04AC-F931-8D56 --trust-fingerprint

# Your friend: connect with your fingerprint + trust
simplecipher connect --peer-fingerprint A3F2-91BC-D4E5-F678 --trust-fingerprint
```

---

### Over Tor

**What this is.** [Tor](docs/GLOSSARY.md#tor) is free software that hides your [IP address](docs/GLOSSARY.md#ip-address) (the number that identifies your computer on the network). Without Tor, your internet provider and anyone watching the network can see *that* you are connecting to your friend, even though they cannot read your messages. With Tor, nobody can see who is talking to whom.

Think of it like mailing a letter through a chain of intermediaries, each one only knowing the next step. Nobody sees both the sender and the recipient.

**Verification:** [Safety code](docs/GLOSSARY.md#safety-code) -- you compare a short code over the phone. Takes 10 seconds.

**Steps for the person connecting:**

1. Install Tor: `sudo apt install tor` (Linux) or download from [torproject.org](https://www.torproject.org/).
2. Start the Tor service: `sudo systemctl start tor`
3. Your friend gives you their `.onion` address (a special Tor address).
4. Connect through Tor.
5. Compare the safety code over a phone call.

```bash
# Connect through Tor (type the .onion address when prompted):
simplecipher connect --socks5 127.0.0.1:9050
```

**Steps for the person listening (setting up an onion service):**

1. Install Tor: `sudo apt install tor`
2. Edit the Tor configuration file (`/etc/tor/torrc`) and add these two lines:

```
HiddenServiceDir /var/lib/tor/simplecipher/
HiddenServicePort 7777 127.0.0.1:7777
```

3. Restart Tor: `sudo systemctl restart tor`
4. Find your `.onion` address: `cat /var/lib/tor/simplecipher/hostname`
5. Send the `.onion` address to your friend through a secure channel.
6. Start listening with cover traffic:

```bash
simplecipher listen --cover-traffic
```

**What is [cover traffic](docs/GLOSSARY.md#cover-traffic)?** `--socks5` automatically sends encrypted empty messages at random intervals, even when you are not typing. Without this, someone watching the network can match *when* you type to *when* encrypted data flows through Tor -- and figure out who is talking to whom. With cover traffic, data flows constantly, so your typing pattern disappears into the noise. Listeners behind onion services should add `--cover-traffic` explicitly (since they don't use `--socks5`).

See the [Tor onion services documentation](https://community.torproject.org/onion-services/setup/) for more details on onion service setup.

---

### Over Tor with pre-shared fingerprints

**What this is.** The strongest option. You get full anonymity from Tor *and* verified identity from pre-shared fingerprints. Nobody can see who is talking to whom, and you know for certain it is your friend on the other end.

**Verification:** [Fingerprint](docs/GLOSSARY.md#fingerprint) verified first, then [safety code](docs/GLOSSARY.md#safety-code). Both layers, plus Tor anonymity.

**Steps:**

1. Exchange fingerprints on paper when you meet in person.
2. Set up Tor (see [Over Tor](#over-tor) above for the full Tor setup).
3. Use both `--peer-fingerprint` and Tor together.

```bash
# You: listen as a Tor onion service with your friend's fingerprint
simplecipher listen --cover-traffic --peer-fingerprint B7E2-04AC-F931-8D56

# Your friend: connect through Tor with your fingerprint
simplecipher connect --socks5 127.0.0.1:9050 --peer-fingerprint A3F2-91BC-D4E5-F678
```

You can also add `--trust-fingerprint` on both sides to skip the safety code entirely, making the connection fully automatic.

---

### Which method sees your IP address?

SimpleCipher encrypts your messages, but your [IP address](docs/GLOSSARY.md#ip-address) is still visible to the network. The method you choose determines who can see that you are connecting:

| Method | Who sees your IP |
|--------|------------------|
| **Same Wi-Fi** | Nobody outside the network |
| **Tailscale** | Tailscale's coordination server sees both endpoints |
| **Port forwarding** | Anyone who knows the IP can attempt a connection |
| **Tor** | Neither side learns the other's IP; network observers see Tor traffic but not the destination |

### Options

```bash
# Specify a custom port (default: 7777)
simplecipher listen 9000
simplecipher connect 100.x.y.z 9000

# Split-pane terminal UI with scrolling messages and fixed input line
simplecipher --tui listen
simplecipher --tui connect 100.x.y.z

# Connect through a SOCKS5 proxy (e.g. Tor on 127.0.0.1:9050)
simplecipher connect --socks5 127.0.0.1:9050
#   Host: <onion-address>

# Interactive mode (default) — host stays out of shell history and argv
simplecipher connect
#   Host: 100.70.179.3
#   Port [7777]:

# Verify peer identity with a pre-shared fingerprint (interactive)
simplecipher connect --peer-fingerprint A3F2-91BC-D4E5-F678
#   Host: 100.x.y.z

# Show version and build info
simplecipher --version
```

TUI mode works on Linux, macOS, and Windows 10+. No dependencies — pure ANSI escape sequences.

**[SOCKS5](docs/GLOSSARY.md#socks5) proxy** (`--socks5`): tunnels the connection through any SOCKS5 proxy. Essential for Tor — the proxy resolves DNS, so `.onion` addresses work and no DNS queries leak from your machine.

**Interactive connect**: running `simplecipher connect` without a host prompts for it on stdin. The target address never appears in `argv`, shell history, or `/proc/*/cmdline`.

**Peer [fingerprint](docs/GLOSSARY.md#fingerprint)** (`--peer-fingerprint`): the listener's fingerprint is shown on the listen screen *before* any connection is made, so it can be shared while waiting for a peer. The connector passes it as a flag. After the handshake, the peer's public key is hashed and compared — mismatch aborts the connection. Works for both listen and connect modes. This is optional additional verification on top of the SAS code, useful when you can pre-share a fingerprint but can't make a phone call.

**Trust fingerprint** (`--trust-fingerprint`): when combined with `--peer-fingerprint`, skips the interactive SAS verification entirely if the fingerprint matches. The 64-bit fingerprint is cryptographically stronger than the 32-bit SAS code, so this is safe when the fingerprint was exchanged through a trusted channel (e.g., paper, in person). Both sides can use it for fully non-interactive mutual verification:

```bash
# Alice (listener) has Bob's fingerprint on paper:
simplecipher listen --peer-fingerprint B7E2-04AC-F931-8D56 --trust-fingerprint

# Bob (connector) has Alice's fingerprint on paper:
simplecipher connect --peer-fingerprint A3F2-91BC-D4E5-F678 --trust-fingerprint 192.168.1.208
```

On Android, the same flow happens through the app UI: choose Listen or Connect, enter the host/port, verify the safety code, and chat.

### Exit codes

For scripting and automation, SimpleCipher uses distinct exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success (clean shutdown) |
| 1 | Usage error (bad arguments) |
| 2 | Network error (connection failed, timeout) |
| 3 | Handshake failure (protocol mismatch, commitment mismatch) |
| 4 | MITM detected (safety code rejected or peer fingerprint mismatch) |
| 5 | Sandbox error (`--require-sandbox` and sandbox installation failed) |
| 6 | Internal error |
| 7 | SAS aborted (timeout, Ctrl+D, or Ctrl+C during verification) |

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
| **Paper with fingerprint** (best) | Exchange `--peer-fingerprint` codes on paper when you meet. Paper can't be hacked — no network, no device, no interception. **Note:** fingerprints are ephemeral — they change every session. Exchange new ones each time you meet. |
| **Video call** | You see and hear the person — very hard to fake in real time |
| **Voice call** | You recognize their voice — good if you know them well |
| **Pre-shared fingerprint via Signal/secure chat** | Shared digitally in advance — only as secure as that channel |
| **Text message** | Weakest — an attacker who controls the network might also control SMS. Better than nothing. |

**Why this matters:** The safety code is how you know you're actually talking to your friend and not to someone pretending to be them. Without this check, an attacker sitting between you could read everything. This is the single most important step — don't skip it.

```
  You verify the code:             You skip verification:

  Alice ------- Bob                Alice --- Eve --- Bob
  Code: 9052-EF29                  Alice sees: 9052-EF29
  Both see the same code           Bob sees:   7A31-B4C0
  +-> Codes match = safe           Nobody compares the codes
                                   +-> Eve reads everything
```

Always compare the code. If it matches, you are safe. If you skip it, someone could be listening.

### Understanding fingerprints and safety codes

SimpleCipher has two ways to check that you are really talking to your friend: **safety codes** and **fingerprints**. They work differently and are used at different times.

**Safety code -- compare it right now, over the phone.**
When you connect, both screens show the same short code (like `9052-EF29`). You call your friend and read it out loud. If it matches, you are safe. The safety code only exists during this one session. It proves nobody is secretly sitting between you right now.

**Fingerprint -- exchange it on paper when you meet in person.**
A fingerprint is another short code (like `A3F2-91BC-D4E5-F678`). You see it when you run `simplecipher listen`. When you and your friend are together in the same room, you each write down your own fingerprint and hand it to each other. Later, when you chat from different locations, SimpleCipher checks the fingerprint automatically. If it does not match, the connection stops.

**Why are there two fingerprints -- one for each person?**
A fingerprint is like a phone number. Yours is different from your friend's. You each have your own. When you meet, you give yours to your friend, and they give theirs to you. Later, SimpleCipher uses the fingerprint your friend gave you to make sure the person connecting is really them. Your friend's copy of SimpleCipher does the same thing with the fingerprint you gave them.

**What if someone finds the paper with a fingerprint on it?**
Nothing bad happens. A fingerprint is not a password. It is more like a phone number -- knowing it does not let anyone read your messages or pretend to be you. The real secret (the encryption key) only exists inside the computer's memory while you are chatting. When you close the program, the key is destroyed. The fingerprint on the paper cannot be used to recover it.

**In short:**

| | Safety code | Fingerprint |
|---|---|---|
| **When** | During the chat session | Before the chat, when you meet in person |
| **How** | Read it out loud on a phone call | Write it on paper and hand it over |
| **What it proves** | Nobody is intercepting this session | The person connecting is the same person you met |
| **If someone steals it** | Only useful during this one session | Useless -- it is not a secret |

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
| [FreeBSD](https://www.freebsd.org/) | Capsicum capability sandbox integrated, CI-tested on bare-metal | Capsicum restricts per-fd operations after `cap_enter()` — no new files or filesystem access. Simpler model than seccomp. Sandbox enforcement CI-verified on bare-metal FreeBSD 14.3 (when bare-metal hosts are configured). |
| [OpenBSD](https://www.openbsd.org/) | Smallest attack surface of any general-purpose OS, `pledge`/`unveil` sandboxing | Secure by default. Fewer things running means fewer things to exploit. Sandbox enforcement CI-verified on bare-metal OpenBSD 7.7 (when bare-metal hosts are configured). |
| Any Linux with full-disk encryption | `mlockall` + [seccomp](docs/PROTOCOL.md#seccomp) enabled, encrypted swap | A fresh Debian, Fedora, or Arch install with no unnecessary services. Encrypt the disk so a stolen laptop reveals nothing. |
| Windows 10/11 with BitLocker | Encrypted disk, standard protections | Better than an unencrypted machine. Less hardening available than Linux. |

**Android:**

| OS | Why |
|----|-----|
| [GrapheneOS](https://grapheneos.org/) | Hardened Android — no Google services, verified boot, improved sandboxing. SimpleCipher's minimal flavor runs without any Google dependencies. |
| Stock Android | Standard security. The app's built-in protections (screenshot blocking, custom keyboard, session kill on background) help, but the OS is not designed for high-security use. |

**If you're just getting started:** a standard Linux or Windows machine with full-disk encryption is a solid baseline. If your threat model demands more, move up the table.

## FAQ

**Can someone read my messages?**
Not if you compare the safety code. The encryption uses the same industry-standard algorithms as Signal and WhatsApp ([X25519](docs/PROTOCOL.md#x25519), [XChaCha20-Poly1305](docs/PROTOCOL.md#xchacha20-poly1305)). The code has been tested with 680 automated tests, formally verified with CBMC, and the crypto library ([Monocypher](https://monocypher.org/)) has been [professionally audited](https://monocypher.org/quality-assurance/audit). That said, SimpleCipher itself has not been independently audited as a complete system. If your safety depends on this tool, commission a professional audit first.

**Can someone intercept the connection?**
They can try, but the safety code comparison stops them. Both sides lock in their keys before revealing them, then derive a code that must match. If it matches, no one is in the middle. If you skip the comparison, all bets are off.

**What happens if I lose connection?**
The session is gone. Keys exist only in memory. Reconnect and start fresh — you'll get a new code.

**Why not just use Signal?**
Signal requires a phone number, an account, and a central server that knows who talks to whom. SimpleCipher has none of that. Nothing is stored, no sign-up needed. Use Signal when you need persistent contacts. Use SimpleCipher when storing nothing to disk matters more.

**Can I use this over the internet without a VPN?**
Yes, if one side has a reachable IP (port forwarding, cloud server, etc.). See [Ways to use SimpleCipher](#ways-to-use-simplecipher) for options. For anonymity, use [Tor](#over-tor).

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

Every release artifact also has a **detached cosign signature** (`.sig` + `.cert` files). These are keyless Sigstore signatures tied to the GitHub Actions OIDC identity — no personal key to steal.

```bash
# Verify a detached signature (requires cosign):
cosign verify-blob simplecipher-linux-x86_64 \
  --signature simplecipher-linux-x86_64.sig \
  --certificate simplecipher-linux-x86_64.cert \
  --certificate-identity-regexp "https://github.com/robinvanemden/simplecipher" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

SHA256 checksums are also provided in `SHA256SUMS.txt` (and signed) for quick integrity checks.

### Maintainer signatures (optional second layer)

CI signatures prove the artifact came from this repository's workflow.
Maintainer signatures add a second check — but only if the maintainer independently verifies or rebuilds the artifacts before signing. The provided `scripts/sign-release.sh` downloads CI artifacts and signs them in place; by itself, that does not defeat a compromised workflow. For stronger assurance, the maintainer should rebuild from source and compare checksums before signing.

When available, `.minisig` files are attached to the release:

```bash
# Verify with minisign (maintainer pubkey published separately):
minisign -Vm simplecipher-linux-x86_64 -p <pubkey>
```

## License

[MIT](LICENSE) — Monocypher is [BSD-2-Clause / CC0](lib/monocypher.h).
