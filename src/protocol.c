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

/* ---- input validation --------------------------------------------------- */

/* Return 1 if s is a decimal integer in [1, 65535], 0 otherwise.
 * getaddrinfo silently accepts names, negatives, and out-of-range values;
 * this check ensures a typo produces a clear error message. */
[[nodiscard]] int validate_port(const char *s){
    char *end;
    long n;
    if (!s || !*s) return 0;
    n = strtol(s, &end, 10);
    return *end == '\0' && n >= 1 && n <= 65535;
}

/* ---- peer output sanitisation ------------------------------------------- */

/* Replace non-printable bytes in a peer message with '.' before printing.
 *
 * An authenticated peer could embed ANSI / OSC escape sequences to rewrite
 * the screen, spoof the prompt, or access the clipboard on some terminals.
 * We allow printable ASCII (0x20-0x7E) and tab (0x09) only.
 * All other bytes -- including ESC (0x1B) -- become '.'. */
void sanitize_peer_text(uint8_t *buf, uint16_t len){
    uint16_t i;
    for (i = 0; i < len; i++)
        if (buf[i] != 0x09 && (buf[i] < 0x20 || buf[i] > 0x7E))
            buf[i] = '.';
}

/* ---- protocol ----------------------------------------------------------- */

/* Generate a fresh ephemeral X25519 keypair from the OS CSPRNG.
 * Ephemeral means one session only, never stored.  Past sessions cannot
 * be decrypted after the private key is wiped. */
void gen_keypair(uint8_t priv[KEY], uint8_t pub[KEY]){
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
[[nodiscard]] int session_init(session_t *s, int we_init,
                               const uint8_t self_priv[KEY],
                               const uint8_t self_pub[KEY],
                               const uint8_t peer_pub[KEY],
                               uint8_t sas_key_out[KEY]){
    uint8_t dh[KEY];
    crypto_x25519(dh, self_priv, peer_pub);
    if (is_zero32(dh)){ crypto_wipe(dh, sizeof dh); return -1; }

    uint8_t prk[KEY], ikm[KEY * 3];
    /* Canonical ordering (initiator first) so both sides build identical IKM. */
    const uint8_t *init_pub = we_init ? self_pub : peer_pub;
    const uint8_t *resp_pub = we_init ? peer_pub : self_pub;
    memcpy(ikm,         dh,       KEY);
    memcpy(ikm + KEY,   init_pub, KEY);
    memcpy(ikm + KEY*2, resp_pub, KEY);
    domain_hash(prk, "cipher x25519 sas root v1", ikm, sizeof ikm);

    expand(sas_key_out,  prk, "sas");
    expand(s->tx,        prk, we_init ? "init->resp" : "resp->init");
    expand(s->rx,        prk, we_init ? "resp->init" : "init->resp");
    s->tx_seq = 0;
    s->rx_seq = 0;

    crypto_wipe(dh,  sizeof dh);
    crypto_wipe(prk, sizeof prk);
    crypto_wipe(ikm, sizeof ikm);
    return 0;
}

/* Wipe the entire session state at shutdown. */
void session_wipe(session_t *s){ crypto_wipe(s, sizeof *s); }

/* Encrypt one message into a fixed 512-byte frame.
 *
 * Frame: [ seq(8) | ciphertext(488) | mac(16) ]
 * Plaintext slot: [ len(2) | message | zeros to fill 488 bytes ]
 * Fixed size hides message length from network observers.
 *
 * next_chain is computed but the caller does NOT advance the chain until
 * the write succeeds -- "commit after successful send" keeps both sides
 * in sync even if a send fails midway. */
[[nodiscard]] int frame_build(const uint8_t chain[KEY], uint64_t seq,
                              const uint8_t *plain, uint16_t len,
                              uint8_t frame[FRAME_SZ], uint8_t next_chain[KEY]){
    if (len > MAX_MSG) return -1;

    uint8_t mk[KEY], ad[AD_SZ], nonce[NONCE_SZ], pt[CT_SZ];
    chain_step(chain, mk, next_chain);
    le64_store(ad, seq);
    make_nonce(nonce, seq);

    memset(pt, 0, sizeof pt);
    pt[0] = (uint8_t)(len & 0xff);
    pt[1] = (uint8_t)(len >> 8);
    if (len) memcpy(pt + 2, plain, len);

    memcpy(frame, ad, AD_SZ);
    crypto_aead_lock(frame + AD_SZ,         /* ciphertext */
                     frame + AD_SZ + CT_SZ, /* mac        */
                     mk, nonce, ad, AD_SZ, pt, CT_SZ);

    crypto_wipe(mk,    sizeof mk);
    crypto_wipe(pt,    sizeof pt);
    crypto_wipe(nonce, sizeof nonce);
    return 0;
}

/* Decrypt and authenticate one 512-byte frame.
 *
 * Sequence number is checked first (cheap) to reject replays without any
 * crypto work.  The chain advances only after the MAC passes -- a forged
 * frame leaves session state untouched.
 *
 * Returns 0 on success (out and out_len filled), -1 on any failure. */
[[nodiscard]] int frame_open(session_t *s, const uint8_t frame[FRAME_SZ],
                             uint8_t *out, uint16_t *out_len){
    uint64_t seq = le64_load(frame);
    if (seq != s->rx_seq) return -1;   /* replay / reorder -- reject */

    uint8_t mk[KEY], next_rx[KEY], nonce[NONCE_SZ], pt[CT_SZ];
    uint16_t len;
    chain_step(s->rx, mk, next_rx);
    make_nonce(nonce, seq);

    if (crypto_aead_unlock(pt,
                           frame + AD_SZ + CT_SZ,
                           mk, nonce,
                           frame, AD_SZ,
                           frame + AD_SZ, CT_SZ) != 0){
        crypto_wipe(mk, sizeof mk); crypto_wipe(next_rx, sizeof next_rx);
        crypto_wipe(pt, sizeof pt); crypto_wipe(nonce, sizeof nonce);
        return -1;
    }

    len = (uint16_t)(pt[0] | (pt[1] << 8));
    if (len > MAX_MSG){
        crypto_wipe(mk, sizeof mk); crypto_wipe(next_rx, sizeof next_rx);
        crypto_wipe(pt, sizeof pt); crypto_wipe(nonce, sizeof nonce);
        return -1;
    }

    /* Auth passed -- now safe to advance the chain. */
    memcpy(s->rx, next_rx, KEY);
    s->rx_seq++;
    if (out)     memcpy(out, pt + 2, len);
    if (out_len) *out_len = len;

    crypto_wipe(mk, sizeof mk); crypto_wipe(next_rx, sizeof next_rx);
    crypto_wipe(pt, sizeof pt); crypto_wipe(nonce, sizeof nonce);
    return 0;
}
