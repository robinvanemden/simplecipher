# Design Spec: Documentation for All Audiences

**Date:** 2026-03-27
**Goal:** Make SimpleCipher docs accurate, in sync with code, welcoming to first-time users, useful for students, and rigorous enough for expert cryptographers — without scaring anyone away.

## Guiding Principles

1. **Noobs come first.** Every document a casual user might open (README, FAQ, ANDROID, DEPLOYMENT) must be understandable without any technical background. If someone just wants to download a binary and chat securely, they should never hit a wall of jargon.
2. **Students can follow the trail.** Jargon is never left unexplained — it's either defined inline in plain English or linked to the glossary. A motivated student can start at the README, follow links deeper, and learn real cryptography along the way.
3. **Experts get rigor in a dedicated place.** Formal security analysis (proofs, reductions, game-based definitions) lives in its own document. It doesn't clutter the docs that beginners and developers read.
4. **One source of truth per concept.** Define a term once (in the glossary), link to it everywhere. No conflicting definitions across files.
5. **Short sentences, active voice, no filler.** Every paragraph earns its place.

## Deliverables

### 1. New file: `docs/GLOSSARY.md`

Single-source reference for every technical term used across the project.

**Structure:**
```markdown
# Glossary

> Look up any technical term used in SimpleCipher's documentation.
> Terms are grouped by topic. If you're brand new, start with "The Basics."

## The Basics
Terms anyone needs to understand what SimpleCipher does.

### Encryption
Scrambling a message so only the intended recipient can read it. [...]

### End-to-end encryption (E2EE)
Encryption where only the two people chatting can read messages — not
the network, not a server, not even SimpleCipher. [...]

## Cryptography
Terms used in the protocol documentation.

### AEAD (Authenticated Encryption with Associated Data)
[...]

## Systems Security
Terms used in the hardening and threat model documentation.

### ASLR (Address Space Layout Randomization)
[...]
```

**Coverage (~50 terms across three groups):**

| Group | Example terms | Audience |
|-------|--------------|----------|
| The Basics (~12) | encryption, key, hash, plaintext, ciphertext, ephemeral, MITM, forward secrecy, fingerprint, session, port, IP address | Anyone |
| Cryptography (~20) | AEAD, KDF, X25519, Diffie-Hellman, ratchet, double ratchet, commitment scheme, post-compromise security, nonce, MAC, SAS, BLAKE2b, XChaCha20-Poly1305, symmetric/asymmetric, PRF, CDH | Students, developers |
| Systems Security (~18) | ASLR, RELRO, PIE, DEP, W^X, seccomp, Capsicum, pledge/unveil, CFI, CET, BTI, DPI, SOCKS5, cover traffic, stack canary, LTO, musl, sanitizer | Developers, auditors |

**Writing rules:**
- Each definition: 1-3 sentences, plain English first, then the precise meaning
- Pattern: "What it is in everyday language → what it means technically → why SimpleCipher uses it"
- "See also" link to the doc where it's used most
- No forward references to terms not yet defined (within each group, order dependencies correctly)

### 2. New file: `docs/FORMAL_ANALYSIS.md`

Protocol-level security arguments in standard cryptographic notation, for academic reviewers, auditors, and advanced students.

**Structure:**
```markdown
# Formal Security Analysis

> **Audience:** Cryptographers, security researchers, and students of
> provable security. This document states SimpleCipher's security
> properties in formal terms. For a plain-English overview, see
> [PROTOCOL.md](PROTOCOL.md). For definitions of terms, see
> [GLOSSARY.md](GLOSSARY.md).

## 1. Notation and conventions
## 2. Security definitions
   - IND-CCA2 and INT-CTXT for the AEAD frame format
   - Session-key indistinguishability for the handshake
## 3. Cryptographic assumptions
   - CDH for X25519
   - PRF security of BLAKE2b in keyed mode
   - AEAD security of XChaCha20-Poly1305
   - References to published proofs for each primitive
## 4. Commitment scheme analysis
   - Binding property: formal argument
   - SAS entropy: 2^{-32} MITM probability per session
   - Why 32-bit is acceptable for interactive verification
## 5. Ratchet security
   - Forward secrecy: compromise of current key reveals nothing about past
   - Post-compromise security: recovery within 1 DH round-trip
   - Chain ratchet: KDF chain provides per-message forward secrecy
## 6. Frame format security
   - AEAD composition: how nonce, key, and AD are derived
   - Replay rejection: monotonic counter argument
   - Tamper detection: MAC verification before any processing
## 7. Known limitations (formally stated)
   - MAC tolerance window: 3 consecutive failures before teardown
   - No post-quantum security (CDH assumption broken by Shor's algorithm)
   - No deniability (commitment scheme is binding)
   - 32-bit SAS: adequate for interactive but not automated verification
   - Cover traffic: timing analysis bounds
## 8. References
   - Signal Double Ratchet spec (Trevor Perrin & Moxie Marlinspike)
   - Monocypher audit report
   - Relevant ePrint papers for each primitive
```

**Writing rules:**
- Standard cryptographic notation (security games, advantage functions, negligible probability)
- Each claim either has a proof sketch or an explicit reference
- "Known limitations" are stated as formally as the security properties — no hiding weaknesses
- Opens with a clear audience statement and links back to plain-English docs

### 3. Intro paragraphs added to existing technical docs

Add a 2-4 sentence plain-English "what this document is and who needs it" paragraph to the top of docs that currently jump straight into technical content. These intros tell beginners whether to keep reading or skip to something more appropriate.

| Document | Current opening | Add |
|----------|----------------|-----|
| `docs/HARDENING.md` | Jumps into security notes | Add intro: "SimpleCipher ships with many layers of protection built in — you don't need to configure anything. This document lists every security measure in detail for auditors and developers. **If you just want to chat securely, you don't need to read this.** See the [README](../README.md) to get started." Also add glossary links on first use of each acronym in tables (e.g., `[RELRO](GLOSSARY.md#relro)`). |
| `docs/THREAT_MODEL.md` | Jumps into guarantees table | "Every security tool has limits. This document honestly states what SimpleCipher protects against, what it doesn't, and why. **If you're evaluating whether SimpleCipher is right for your situation**, start here. For technical terms, see the [Glossary](GLOSSARY.md)." |
| `docs/ASSURANCE_MAP.md` | Jumps into property table | "This is the evidence map — it shows exactly how each security claim is verified (tests, fuzzing, formal proofs, manual review). **If you want to trust SimpleCipher's claims, this is the receipt.** For definitions of terms used here, see the [Glossary](GLOSSARY.md)." |
| `docs/BUILDING.md` | "Audience: Developers" | Fine as-is — already states its audience. Just add glossary links for `musl`, `constexpr`, `-DCIPHER_HARDEN`. |

### 4. Inline glossary links throughout all docs

Every technical term's **first occurrence** in each document becomes a Markdown link to the glossary.

**Rules:**
- Only the first occurrence per document — not every instance (avoids link spam)
- Use standard Markdown: `[AEAD](GLOSSARY.md#aead)` for files inside `docs/`, or `[AEAD](docs/GLOSSARY.md#aead)` for files in the project root
- Terms in code blocks or command examples are NOT linked (they're literal)
- Group common linked terms at the top when a paragraph introduces several at once

**Files to update (all `.md` in project root and `docs/`):**
- README.md
- SECURITY.md
- docs/PROTOCOL.md
- docs/HARDENING.md
- docs/THREAT_MODEL.md
- docs/ASSURANCE_MAP.md
- docs/BUILDING.md
- docs/DEPLOYMENT.md
- docs/DESIGN_BOUNDARIES.md
- docs/ANDROID.md
- docs/WALKTHROUGH.md

### 5. ~~Fix FAQ.md broken link~~

**Not needed.** Investigation confirmed the link `README.md#faq` (lowercase) is already correct — it points to `## FAQ` at README.md line 257. GitHub normalizes anchors to lowercase.

### 6. README.md beginner flow improvement

The README is the front door. Currently it opens well but mixes audience levels mid-document. Changes:

- Add a one-line "What is this?" sentence before the feature list for people who don't know what E2EE is
- Ensure the first 30 lines are completely jargon-free (link any technical terms to glossary)
- Add a "New to cryptography?" callout after the quick-start section pointing to WALKTHROUGH.md and GLOSSARY.md
- Keep the existing deep sections (protocol summary, hardening table) but add glossary links

## What we're NOT doing

- **Not rewriting existing docs.** They're factually accurate and well-structured. We're adding access layers, not replacing content.
- **Not duplicating content across audience tracks.** One glossary, one formal analysis, inline links everywhere. No parallel doc sets that drift out of sync.
- **Not adding formal proofs for Monocypher primitives.** X25519, XChaCha20-Poly1305, and BLAKE2b have published security proofs. FORMAL_ANALYSIS.md references those papers and proves the *protocol composition*.
- **Not dumbing down technical docs.** HARDENING.md stays technical. We just add a welcoming intro and link jargon so beginners aren't stranded.

## File inventory (final state)

| File | Action |
|------|--------|
| `docs/GLOSSARY.md` | **New** — ~50 term definitions |
| `docs/FORMAL_ANALYSIS.md` | **New** — protocol security analysis |
| `README.md` | Edit — beginner flow, glossary links |
| `FAQ.md` | No change — link confirmed correct |
| `SECURITY.md` | Edit — glossary links |
| `docs/PROTOCOL.md` | Edit — glossary links |
| `docs/HARDENING.md` | Edit — intro paragraph, glossary links |
| `docs/THREAT_MODEL.md` | Edit — intro paragraph, glossary links |
| `docs/ASSURANCE_MAP.md` | Edit — intro paragraph, glossary links |
| `docs/BUILDING.md` | Edit — glossary links |
| `docs/DEPLOYMENT.md` | Edit — glossary links |
| `docs/DESIGN_BOUNDARIES.md` | Edit — glossary links |
| `docs/ANDROID.md` | Edit — glossary links |
| `docs/WALKTHROUGH.md` | Edit — glossary links |
| `CLAUDE.md` | No change (developer-only, not public-facing) |

## Implementation approach

Dispatch parallel agents:
1. **Agent: GLOSSARY.md** — write the full glossary from scratch
2. **Agent: FORMAL_ANALYSIS.md** — write the formal analysis, reading protocol.h/c, crypto.h/c, ratchet.h/c for precise details
3. **Agent: Intro paragraphs** — add plain-English intros to HARDENING, THREAT_MODEL, ASSURANCE_MAP
4. **Agent: Inline links (batch 1)** — README, PROTOCOL, WALKTHROUGH, DESIGN_BOUNDARIES
5. **Agent: Inline links (batch 2)** — HARDENING, THREAT_MODEL, ASSURANCE_MAP, BUILDING, DEPLOYMENT, ANDROID, SECURITY
6. **Agent: Fixes** — FAQ.md anchor fix, README beginner flow

Agents 1-2 run first (they create the link targets). Agents 3-6 run after (they link to those targets).
