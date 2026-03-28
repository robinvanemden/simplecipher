# Design Boundaries — SimpleCipher

> **Audience:** Anyone wondering why SimpleCipher does or doesn't have a particular feature.

## What SimpleCipher is

SimpleCipher is a tool for one conversation between two people who can verify each other's identity. It stores nothing to disk and wipes keys from memory on exit, but it cannot guarantee zero OS-level traces (see caveats below).

## What SimpleCipher is not

SimpleCipher is not Signal, WhatsApp, or any persistent messaging system. The differences are intentional:

| Feature | Signal | SimpleCipher | Why |
|---------|--------|--------------|-----|
| Accounts | Phone number required | None | An account is a forensic artifact — proof you use the tool |
| Server | Central server routes messages | None — direct peer-to-peer | A server knows who talks to whom and when |
| Contacts | Stored on device | None | A contact list is a social graph on disk |
| Message history | Stored (encrypted) on device | None — gone when session ends | Stored messages can be compelled or seized |
| Identity keys | Long-term, pinned | [Ephemeral](GLOSSARY.md#ephemeral) by default; optional persistent keys via [keygen](GLOSSARY.md#identity-key) | A stored key is a target for impersonation if seized |
| Group chat | Yes | No — two people only | Groups add complexity and weaken the trust model |
| File transfer | Yes | No — text only | File handling is a large attack surface |
| Offline messages | Yes | No — both must be online | Offline delivery requires a server |

## Core design principles

**Ephemeral.** Every key, every secret, every message exists only in memory, only during the session. When the session ends, the desktop CLI calls `crypto_wipe()` to zero all buffers. Nothing is intentionally written to disk. However, the OS may still leave traces: swap files, terminal scrollback, shell history (mitigated by `mlockall`, interactive prompts, and scrollback purge, but not eliminated — see [PROTOCOL.md](PROTOCOL.md) "What it does NOT provide"). On Android, JVM garbage collection means sensitive data may linger in heap memory beyond the app's control.

**Stateless.** No configuration files, no databases, no saved preferences. The binary runs with zero setup. This eliminates an entire class of bugs (corrupted state, migration errors, backup leaks) and reduces the forensic footprint — though the binary itself on disk is evidence the tool was used.

**Serverless.** Both peers connect directly over TCP. No relay, no push notification service, no coordination server. This means both people must be online at the same time and one must have a reachable IP — but it also means no third party handles the message content. Note: IP addresses are visible to the network and to each peer unless Tor is used (desktop via `--socks5`, Android via Orbot — see [ANDROID.md](ANDROID.md) "SOCKS5 / Tor support"). Network metadata (who connected to whom, when, for how long) is observable by anyone on the network path.

**Auditable.** The entire protocol is implemented in a handful of focused C modules, totaling ~7,000 lines of code. The single cryptographic dependency (Monocypher) is vendored and has been professionally audited. The codebase is designed to be read and understood in an afternoon.

**Minimal.** No TLS library, no HTTP stack, no JSON parser, no package manager dependencies. The desktop binary is ~80 KB with zero runtime dependencies. Every line of code that doesn't exist is a line that can't have bugs.

## Why not just add X?

Common feature requests and why they conflict with the design:

**"Add persistent identity keys"** — This is now available as an opt-in feature via `simplecipher keygen` and `--identity`. A passphrase-protected key file provides a stable [fingerprint](GLOSSARY.md#fingerprint) across sessions, enabling pre-shared paper verification with `--peer-fingerprint` and fully non-interactive sessions with `--trust-fingerprint`. The tradeoff: a stored key file is a forensic artifact (proof you use the tool) and an impersonation target if seized. Without `--identity`, keys remain fully [ephemeral](GLOSSARY.md#ephemeral) — generated fresh each session, never written to disk.

**"Add a server for offline messages"** — A server is a single point of surveillance, compromise, and subpoena. SimpleCipher's value is that no third party is involved.

**"Add group chat"** — Groups require key distribution protocols, membership management, and trust decisions that fundamentally change the security model. Two-person chat has clean, provable properties.

**"Add file transfer"** — File parsing (images, documents, archives) is one of the largest attack surfaces in any application. Text-only keeps the attack surface minimal.

**"Store the session key for reconnection"** — A stored key is a stored secret. If the device is seized between sessions, the attacker gets the key. Ephemeral keys mean there is nothing to find.

**"Add a GUI on desktop"** — A GUI framework (Qt, GTK, Electron) adds millions of lines of code, dynamic linking, and attack surface. The terminal interface has zero dependencies and is auditable.

## When to use SimpleCipher

- You need a private conversation that stores nothing to disk on either device
- You can reach the other person over TCP (same network, VPN, Tor, port forward)
- You can verify their identity through another channel (phone call, in person, pre-shared fingerprint)
- You don't need message history, contacts, or offline delivery

## When to use something else

- You need persistent contacts and message history → **Signal**
- You need group messaging → **Signal** or **Matrix**
- You need file transfer → **Signal** or **Magic Wormhole**
- You need asynchronous messaging (offline delivery) → **Signal**
- You need anonymity without Tor setup → **Briar** (peer-to-peer over Tor by default)
