/*
 * ratchet.c — DH ratchet implementation
 *
 * Implements the three ratchet operations declared in ratchet.h:
 * initialization, send-side ratchet, and receive-side ratchet.
 *
 * All cryptographic primitives come from crypto.h (domain_hash, expand)
 * which in turn use BLAKE2b from Monocypher.  X25519 is from Monocypher
 * directly.
 */

#include "ratchet.h"

/* Internal: perform one DH ratchet step.
 *
 * Mixes a fresh X25519 shared secret into the root key and derives a
 * new chain key.  Used by both ratchet_send (new sending chain) and
 * ratchet_receive (new receiving chain).
 *
 * KDF construction:
 *   dh_secret  = X25519(our_priv, their_pub)         [32 bytes, fixed]
 *   ikm        = root_key || dh_secret                [64 bytes, fixed]
 *   new_root   = domain_hash("cipher ratchet v2", ikm)
 *   new_chain  = expand(new_root, "chain")
 *
 * Both inputs to the concatenation are exactly 32 bytes, so the boundary
 * is unambiguous and no length prefix is needed.
 *
 * The label "cipher ratchet v2" matches PROTOCOL_VERSION=2 and is
 * domain-separated from the handshake labels ("cipher x25519 sas root v1",
 * "cipher commit v1") which use "v1". */
static void ratchet_step(uint8_t root[KEY], uint8_t chain_out[KEY],
                          const uint8_t our_priv[KEY],
                          const uint8_t their_pub[KEY]){
    uint8_t dh[KEY], ikm[KEY * 2];

    crypto_x25519(dh, our_priv, their_pub);

    memcpy(ikm,       root, KEY);
    memcpy(ikm + KEY, dh,   KEY);
    domain_hash(root, "cipher ratchet v2", ikm, sizeof ikm);
    expand(chain_out, root, "chain");

    crypto_wipe(dh,  sizeof dh);
    crypto_wipe(ikm, sizeof ikm);
}

void ratchet_init(session_t *s, int we_init,
                  const uint8_t self_priv[KEY],
                  const uint8_t self_pub[KEY],
                  const uint8_t peer_pub[KEY]){
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
    (void)we_init;
    memcpy(s->dh_priv, self_priv, KEY);
    memcpy(s->dh_pub,  self_pub,  KEY);

    s->need_send_ratchet = 1;  /* first send must ratchet */
}

int ratchet_send(session_t *s, uint8_t ratchet_pub[KEY]){
    if (!s->need_send_ratchet) return 0;

    /* Generate a fresh X25519 keypair for this ratchet step. */
    fill_random(s->dh_priv, KEY);
    crypto_x25519_public_key(s->dh_pub, s->dh_priv);

    /* Mix the new DH secret into the root key and derive a fresh tx chain. */
    ratchet_step(s->root, s->tx, s->dh_priv, s->peer_dh);

    /* Tell the caller to include our new public key in the frame. */
    memcpy(ratchet_pub, s->dh_pub, KEY);

    s->need_send_ratchet = 0;
    return 1;
}

void ratchet_receive(session_t *s, const uint8_t peer_new_pub[KEY]){
    /* Store the peer's new ratchet public key. */
    memcpy(s->peer_dh, peer_new_pub, KEY);

    /* Mix the DH secret into the root key and derive a fresh rx chain. */
    ratchet_step(s->root, s->rx, s->dh_priv, s->peer_dh);
}
