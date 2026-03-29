/*
 * ratchet.c — DH ratchet implementation
 *
 * Implements the four ratchet operations declared in ratchet.h:
 * initialization, pre-computation (prepare), send-side ratchet,
 * and receive-side ratchet.
 *
 * All cryptographic primitives come from crypto.h (domain_hash, expand)
 * which in turn use BLAKE2b from Monocypher.  X25519 is from Monocypher
 * directly.
 */

#include "ratchet.h"

static const char *const DOMAIN_RATCHET = "cipher ratchet v2";

/* DH ratchet KDF construction (used by ratchet_prepare, ratchet_send fallback,
 * and ratchet_receive — each inline this logic with staged temporaries for
 * transactional state updates):
 *
 *   dh_secret  = X25519(our_priv, their_pub)         [32 bytes, fixed]
 *   ikm        = root_key || dh_secret                [64 bytes, fixed]
 *   new_root   = domain_hash("cipher ratchet v2", ikm)
 *   new_chain  = expand(new_root, "chain")
 *
 * The label "cipher ratchet v2" is a KDF domain label (not a protocol
 * version), domain-separated from the handshake labels. */

void ratchet_init(session_t *s, const uint8_t self_priv[KEY], const uint8_t self_pub[KEY],
                  const uint8_t peer_pub[KEY]) {
    /* Both sides start with peer_dh set to the other's handshake public key.
     * This is a public value (not secret) and is overwritten as soon as the
     * first ratchet key arrives from the peer. */
    memcpy(s->peer_dh, peer_pub, KEY);

    /* Both sides store the handshake keypair as the initial ratchet keypair
     * and set need_send_ratchet=1.  The first frame_build on either side
     * will trigger ratchet_send, which generates a fresh keypair, performs
     * a DH ratchet step, and includes the new public key in the frame
     * (FLAG_RATCHET).  This ensures the peer can derive the matching
     * rx chain from the ratchet key in the first received message.
     *
     * The handshake private key is retained here because it is needed for
     * the first ratchet_receive DH computation when the peer's ratchet
     * key arrives. */
    memcpy(s->dh_priv, self_priv, KEY);
    memcpy(s->dh_pub, self_pub, KEY);

    s->need_send_ratchet = 1; /* first send must ratchet */
    s->ratchet_prepared  = 0;

    /* Pre-compute the first ratchet step eagerly so that the first
     * frame_build has no DH timing asymmetry vs subsequent sends. */
    ratchet_prepare(s);
}

void ratchet_prepare(session_t *s) {
    if (!s->need_send_ratchet) return;

    /* Wipe any previous staged state before overwriting. */
    crypto_wipe(s->staged_dh_priv, KEY);
    crypto_wipe(s->staged_dh_pub, KEY);
    crypto_wipe(s->staged_root, KEY);
    crypto_wipe(s->staged_tx, KEY);

    /* Generate a fresh X25519 keypair. */
    uint8_t new_priv[KEY], new_pub[KEY];
    fill_random(new_priv, KEY);
    crypto_x25519_public_key(new_pub, new_priv);

    /* Compute the full ratchet step: DH + KDF. */
    uint8_t pre_root[KEY];
    memcpy(pre_root, s->root, KEY);

    uint8_t dh[KEY], ikm[KEY * 2];
    crypto_x25519(dh, new_priv, s->peer_dh);
    if (is_zero32(dh)) {
        s->staged_ratchet_ok = -1;
        s->ratchet_prepared  = 1;
        crypto_wipe(dh, sizeof dh);
        crypto_wipe(new_priv, sizeof new_priv);
        crypto_wipe(new_pub, sizeof new_pub);
        crypto_wipe(pre_root, sizeof pre_root);
        return;
    }

    memcpy(ikm, pre_root, KEY);
    memcpy(ikm + KEY, dh, KEY);
    domain_hash(pre_root, DOMAIN_RATCHET, ikm, sizeof ikm);

    uint8_t pre_tx[KEY];
    expand(pre_tx, pre_root, "chain");

    /* Store the pre-computed results in the session. */
    memcpy(s->staged_dh_priv, new_priv, KEY);
    memcpy(s->staged_dh_pub, new_pub, KEY);
    memcpy(s->staged_root, pre_root, KEY);
    memcpy(s->staged_tx, pre_tx, KEY);
    s->staged_ratchet_ok = 0;
    s->ratchet_prepared  = 1;

    crypto_wipe(dh, sizeof dh);
    crypto_wipe(ikm, sizeof ikm);
    crypto_wipe(new_priv, sizeof new_priv);
    crypto_wipe(new_pub, sizeof new_pub);
    crypto_wipe(pre_root, sizeof pre_root);
    crypto_wipe(pre_tx, sizeof pre_tx);
}

int ratchet_send(session_t *s, uint8_t ratchet_pub[KEY]) {
    if (!s->need_send_ratchet) return 0;

    if (s->ratchet_prepared) {
        /* Use the pre-computed ratchet step from ratchet_prepare(). */
        if (s->staged_ratchet_ok != 0) {
            /* Pre-computation detected all-zero DH -- malicious peer. */
            s->ratchet_prepared = 0;
            crypto_wipe(s->staged_dh_priv, KEY);
            crypto_wipe(s->staged_dh_pub, KEY);
            crypto_wipe(s->staged_root, KEY);
            crypto_wipe(s->staged_tx, KEY);
            return -1;
        }

        memcpy(s->dh_priv, s->staged_dh_priv, KEY);
        memcpy(s->dh_pub, s->staged_dh_pub, KEY);
        memcpy(s->root, s->staged_root, KEY);
        memcpy(s->tx, s->staged_tx, KEY);
        memcpy(ratchet_pub, s->staged_dh_pub, KEY);

        s->need_send_ratchet = 0;
        s->ratchet_prepared  = 0;
        crypto_wipe(s->staged_dh_priv, KEY);
        crypto_wipe(s->staged_dh_pub, KEY);
        crypto_wipe(s->staged_root, KEY);
        crypto_wipe(s->staged_tx, KEY);
        return 1;
    }

    /* Fallback: no pre-computation available -- compute from scratch.
     * This should not happen in normal operation, but is kept for safety. */
    uint8_t new_priv[KEY], new_pub[KEY];
    fill_random(new_priv, KEY);
    crypto_x25519_public_key(new_pub, new_priv);

    uint8_t staged_root[KEY], staged_tx[KEY];
    memcpy(staged_root, s->root, KEY);

    uint8_t dh[KEY], ikm[KEY * 2];
    crypto_x25519(dh, new_priv, s->peer_dh);
    if (is_zero32(dh)) {
        crypto_wipe(dh, sizeof dh);
        crypto_wipe(new_priv, sizeof new_priv);
        crypto_wipe(new_pub, sizeof new_pub);
        crypto_wipe(staged_root, sizeof staged_root);
        return -1;
    }

    memcpy(ikm, staged_root, KEY);
    memcpy(ikm + KEY, dh, KEY);
    domain_hash(staged_root, DOMAIN_RATCHET, ikm, sizeof ikm);
    expand(staged_tx, staged_root, "chain");

    /* All validation passed -- commit state atomically. */
    memcpy(s->dh_priv, new_priv, KEY);
    memcpy(s->dh_pub, new_pub, KEY);
    memcpy(s->root, staged_root, KEY);
    memcpy(s->tx, staged_tx, KEY);
    memcpy(ratchet_pub, new_pub, KEY);

    s->need_send_ratchet = 0;

    crypto_wipe(dh, sizeof dh);
    crypto_wipe(ikm, sizeof ikm);
    crypto_wipe(new_priv, sizeof new_priv);
    crypto_wipe(new_pub, sizeof new_pub);
    crypto_wipe(staged_root, sizeof staged_root);
    crypto_wipe(staged_tx, sizeof staged_tx);
    return 1;
}

/* Inlines the DH ratchet KDF with staged temporaries to avoid mutating
 * session state until all validation passes (transactional update). */
int ratchet_receive(session_t *s, const uint8_t peer_new_pub[KEY]) {
    /* Stage all outputs in temporaries -- commit only if DH succeeds.
     * Prevents a malicious low-order ratchet key from poisoning
     * peer_dh/root/rx while callers tolerate the failure. */
    uint8_t staged_root[KEY], staged_rx[KEY];
    memcpy(staged_root, s->root, KEY);

    uint8_t dh[KEY], ikm[KEY * 2];
    crypto_x25519(dh, s->dh_priv, peer_new_pub);
    if (is_zero32(dh)) {
        crypto_wipe(dh, sizeof dh);
        crypto_wipe(staged_root, sizeof staged_root);
        return -1;
    }

    memcpy(ikm, staged_root, KEY);
    memcpy(ikm + KEY, dh, KEY);
    domain_hash(staged_root, DOMAIN_RATCHET, ikm, sizeof ikm);
    expand(staged_rx, staged_root, "chain");

    /* All validation passed -- commit state atomically. */
    memcpy(s->peer_dh, peer_new_pub, KEY);
    memcpy(s->root, staged_root, KEY);
    memcpy(s->rx, staged_rx, KEY);

    crypto_wipe(dh, sizeof dh);
    crypto_wipe(ikm, sizeof ikm);
    crypto_wipe(staged_root, sizeof staged_root);
    crypto_wipe(staged_rx, sizeof staged_rx);
    return 0;
}
