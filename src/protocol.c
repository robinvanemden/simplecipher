/*
 * protocol.c — Chat protocol implementation for SimpleCipher
 *
 * Implements session key derivation, frame encryption/decryption,
 * input validation, and peer text sanitisation as declared in protocol.h.
 *
 * The frame layout is always exactly 512 bytes to hide message length
 * from network observers.  The symmetric ratchet (chain_step from
 * crypto.c) provides per-message forward secrecy.
 */

#include "protocol.h"
#include "ratchet.h"

/* ---- input validation --------------------------------------------------- */

/* Return 1 if s is a decimal integer in [1, 65535], 0 otherwise.
 * getaddrinfo silently accepts names, negatives, and out-of-range values;
 * this check ensures a typo produces a clear error message. */
[[nodiscard]] int validate_port(const char *s) {
    char *end;
    long  n;
    if (!s || !*s) return 0;
    n = strtol(s, &end, 10);
    return *end == '\0' && n >= 1 && n <= 65535;
}

/* ---- cover traffic ------------------------------------------------------ */

int cover_delay_ms(void) {
    uint8_t r[2];
    fill_random(r, 2);
    int d = 500 + ((r[0] | (r[1] << 8)) % 2001);
    crypto_wipe(r, sizeof r);
    return d;
}

/* ---- peer output sanitisation ------------------------------------------- */

/* Replace non-printable bytes in a peer message with '.' before printing.
 *
 * An authenticated peer could embed ANSI / OSC escape sequences to rewrite
 * the screen, spoof the prompt, or access the clipboard on some terminals.
 * We allow printable ASCII (0x20-0x7E) ONLY.
 * All other bytes -- including ESC (0x1B) and tab (0x09) -- become '.'.
 *
 * Tab was previously allowed, but it is still an active terminal control
 * character: it advances the cursor to the next tab stop, which an
 * attacker can use to distort layout and spoof visual structure (e.g.
 * fake timestamps, fake sender labels, or alignment tricks). */
void sanitize_peer_text(uint8_t *buf, uint16_t len) {
    uint16_t i;
    for (i = 0; i < len; i++)
        if (buf[i] < 0x20 || buf[i] > 0x7E) buf[i] = '.';
}

/* ---- protocol ----------------------------------------------------------- */

/* Generate a fresh ephemeral X25519 keypair from the OS CSPRNG.
 * Ephemeral means one session only, never stored.  Past sessions cannot
 * be decrypted after the private key is wiped. */
void gen_keypair(uint8_t priv[KEY], uint8_t pub[KEY]) {
    fill_random(priv, KEY);
    crypto_x25519_public_key(pub, priv);
}

/* Derive all session keys from the X25519 output and both public keys.
 *
 * dh      = X25519(self_priv, peer_pub)
 * ikm     = dh || init_pub || resp_pub   (ikm = "input key material";
 *                                         || means byte concatenation)
 * prk     = domain_hash("cipher x25519 sas root v1", ikm)
 *           (prk = "pseudo-random key" -- a single 32-byte secret that
 *            acts as the root from which all session keys are derived)
 * sas_key = expand(prk, "sas")
 * tx      = expand(prk, "init->resp" or "resp->init")
 * rx      = expand(prk, "resp->init" or "init->resp")
 *
 * Binding both public keys into ikm ensures a MITM who replaces a key
 * produces a different prk and therefore a different safety code.
 *
 * Returns 0, or -1 if dh is all-zero (small-subgroup / malicious key). */
[[nodiscard]] int session_init(session_t *s, int we_init, const uint8_t self_priv[KEY], const uint8_t self_pub[KEY],
                               const uint8_t peer_pub[KEY], uint8_t sas_key_out[KEY]) {
    uint8_t dh[KEY];
    crypto_x25519(dh, self_priv, peer_pub);
    if (is_zero32(dh)) {
        crypto_wipe(dh, sizeof dh);
        return -1;
    }

    uint8_t prk[KEY], ikm[KEY * 3];
    /* Canonical ordering (initiator first) so both sides build identical IKM. */
    const uint8_t *init_pub = we_init ? self_pub : peer_pub;
    const uint8_t *resp_pub = we_init ? peer_pub : self_pub;
    memcpy(ikm, dh, KEY);
    memcpy(ikm + KEY, init_pub, KEY);
    memcpy(ikm + KEY * 2, resp_pub, KEY);
    domain_hash(prk, "cipher x25519 sas root v1", ikm, sizeof ikm);

    /* Derive a root key that persists across DH ratchet steps, then
     * let ratchet_init derive the initial tx/rx chains from root. */
    expand(sas_key_out, prk, "sas");
    expand(s->root, prk, "root");

    /* Derive bootstrap chains for both directions.  These are used for
     * the very first frame from each side, which also carries FLAG_RATCHET
     * to set up the DH-ratcheted chains for subsequent messages.
     *
     * Initiator tx = responder rx ("init->resp" direction)
     * Initiator rx = responder tx ("resp->init" direction) */
    if (we_init) {
        expand(s->tx, s->root, "init->resp");
        expand(s->rx, s->root, "resp->init");
    } else {
        expand(s->tx, s->root, "resp->init");
        expand(s->rx, s->root, "init->resp");
    }
    s->tx_seq = 0;
    s->rx_seq = 0;

    ratchet_init(s, we_init, self_priv, self_pub, peer_pub);

    crypto_wipe(dh, sizeof dh);
    crypto_wipe(prk, sizeof prk);
    crypto_wipe(ikm, sizeof ikm);
    return 0;
}

/* Wipe the entire session state at shutdown. */
void session_wipe(session_t *s) { crypto_wipe(s, sizeof *s); }

/* Encrypt one message into a fixed 512-byte frame.
 *
 * Calls ratchet_send() to check if a DH ratchet step is needed.  If so,
 * the frame's flags byte is set to FLAG_RATCHET and the sender's new
 * ratchet public key is included in the plaintext slot.
 *
 * next_chain is computed but the caller does NOT advance the chain until
 * the write succeeds -- "commit after successful send" keeps both sides
 * in sync even if a send fails midway.
 *
 * Note: ratchet state (root, dh_priv, dh_pub, tx) is mutated inside
 * ratchet_send before the frame is built.  If the subsequent write fails,
 * the session is inconsistent -- this is acceptable because any I/O
 * failure is session-fatal in SimpleCipher. */
[[nodiscard]] int frame_build(session_t *s, const uint8_t *plain, uint16_t len, uint8_t frame[FRAME_SZ],
                              uint8_t next_chain[KEY]) {
    /* Check payload size BEFORE mutating ratchet state.  The first send
     * after a receive triggers a DH ratchet, which embeds a 32-byte public
     * key in the frame — reducing the available payload by KEY bytes.
     * If we checked after ratchet_send(), a too-large message would leave
     * the session in a half-ratcheted state (new keypair generated but
     * never sent to the peer). */
    uint16_t max = s->need_send_ratchet ? MAX_MSG_RATCHET : MAX_MSG;
    if (len > max) return -1;

    /* Now safe to ratchet — we know the payload fits.
     *
     * IMPORTANT: save the pre-ratchet tx chain BEFORE calling ratchet_send.
     * ratchet_send derives a new tx chain for future messages, but THIS
     * frame must be encrypted with the OLD chain — because the receiver's
     * rx still corresponds to the old chain.  The ratchet key we include
     * tells the receiver to derive the new rx for FUTURE messages. */
    uint8_t ratchet_pub[KEY];
    uint8_t encrypt_chain[KEY];
    memcpy(encrypt_chain, s->tx, KEY);
    int ratcheting = ratchet_send(s, ratchet_pub);
    if (ratcheting < 0) return -1; /* all-zero DH — malicious peer */

    uint8_t mk[KEY], ad[AD_SZ], nonce[NONCE_SZ], pt[CT_SZ];
    if (ratcheting) {
        /* Ratcheted: encrypt with old chain, next_chain = ratcheted tx.
         * The caller commits next_chain after send, installing the new
         * ratcheted chain for subsequent messages. */
        uint8_t discard[KEY];
        chain_step(encrypt_chain, mk, discard);
        memcpy(next_chain, s->tx, KEY);
        crypto_wipe(discard, sizeof discard);
    } else {
        chain_step(encrypt_chain, mk, next_chain);
    }
    le64_store(ad, s->tx_seq);
    make_nonce(nonce, s->tx_seq);

    /* Build plaintext slot:
     *   Normal:  [ flags(1) | len(2) | message | zero padding ]
     *   Ratchet: [ flags(1) | ratchet_pub(32) | len(2) | message | padding ] */
    memset(pt, 0, sizeof pt);
    size_t off = 0;
    pt[off++]  = ratcheting ? FLAG_RATCHET : 0;
    if (ratcheting) {
        memcpy(pt + off, ratchet_pub, KEY);
        off += KEY;
    }
    pt[off++] = (uint8_t)(len & 0xff);
    pt[off++] = (uint8_t)(len >> 8);
    if (len) memcpy(pt + off, plain, len);

    memcpy(frame, ad, AD_SZ);
    crypto_aead_lock(frame + AD_SZ, frame + AD_SZ + CT_SZ, mk, nonce, ad, AD_SZ, pt, CT_SZ);

    crypto_wipe(mk, sizeof mk);
    crypto_wipe(pt, sizeof pt);
    crypto_wipe(nonce, sizeof nonce);
    crypto_wipe(ratchet_pub, sizeof ratchet_pub);
    crypto_wipe(encrypt_chain, sizeof encrypt_chain);
    return 0;
}

/* Decrypt and authenticate one 512-byte frame.
 *
 * Sequence number is checked first (cheap) to reject replays without any
 * crypto work.  The chain advances only after the MAC passes -- a forged
 * frame leaves session state untouched.
 *
 * Returns 0 on success (out and out_len filled), -1 on any failure. */
[[nodiscard]] int frame_open(session_t *s, const uint8_t frame[FRAME_SZ], uint8_t *out, uint16_t *out_len) {
    uint64_t seq = le64_load(frame);
    if (seq != s->rx_seq) return -1; /* replay / reorder -- reject */

    uint8_t  mk[KEY], next_rx[KEY], nonce[NONCE_SZ], pt[CT_SZ];
    uint16_t len;
    chain_step(s->rx, mk, next_rx);
    make_nonce(nonce, seq);

    if (crypto_aead_unlock(pt, frame + AD_SZ + CT_SZ, mk, nonce, frame, AD_SZ, frame + AD_SZ, CT_SZ) != 0) {
        crypto_wipe(mk, sizeof mk);
        crypto_wipe(next_rx, sizeof next_rx);
        crypto_wipe(pt, sizeof pt);
        crypto_wipe(nonce, sizeof nonce);
        return -1;
    }

    /* Parse the plaintext slot: flags, optional ratchet key, len, message.
     *
     * IMPORTANT: do not mutate session state until ALL validation passes.
     * ratchet_receive modifies s->root, s->rx, s->peer_dh — so we read
     * the ratchet key position first, validate len, and only then commit
     * all state changes (chain advance + ratchet) in one block. */
    size_t  off   = 0;
    uint8_t flags = pt[off++];

    /* Reject frames with unknown flag bits (forward compatibility). */
    if (flags & ~FLAG_RATCHET) {
        crypto_wipe(mk, sizeof mk);
        crypto_wipe(next_rx, sizeof next_rx);
        crypto_wipe(pt, sizeof pt);
        crypto_wipe(nonce, sizeof nonce);
        return -1;
    }

    /* Note the ratchet key position but don't process it yet. */
    size_t ratchet_off = off;
    if (flags & FLAG_RATCHET) off += KEY;

    len = (uint16_t)(pt[off] | (pt[off + 1] << 8));
    off += 2;

    uint16_t max = (flags & FLAG_RATCHET) ? MAX_MSG_RATCHET : MAX_MSG;
    if (len > max) {
        crypto_wipe(mk, sizeof mk);
        crypto_wipe(next_rx, sizeof next_rx);
        crypto_wipe(pt, sizeof pt);
        crypto_wipe(nonce, sizeof nonce);
        return -1;
    }

    /* All validation passed — now safe to commit state changes.
     *
     * If a ratchet key was present, ratchet_receive derives a fresh rx
     * chain for future messages.  We must NOT overwrite it with next_rx
     * (which is the old chain stepped forward).  For non-ratchet frames,
     * advance the existing chain as before. */
    if (flags & FLAG_RATCHET) {
        if (ratchet_receive(s, pt + ratchet_off) != 0) {
            crypto_wipe(mk, sizeof mk);
            crypto_wipe(next_rx, sizeof next_rx);
            crypto_wipe(pt, sizeof pt);
            crypto_wipe(nonce, sizeof nonce);
            return -1; /* all-zero DH — malicious peer */
        }
    } else memcpy(s->rx, next_rx, KEY);
    s->rx_seq++;
    s->need_send_ratchet = 1;
    if (out) memcpy(out, pt + off, len);
    if (out_len) *out_len = len;

    crypto_wipe(mk, sizeof mk);
    crypto_wipe(next_rx, sizeof next_rx);
    crypto_wipe(pt, sizeof pt);
    crypto_wipe(nonce, sizeof nonce);
    return 0;
}
