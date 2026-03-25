/*
 * ratchet.h — DH ratchet for post-compromise security
 *
 * This module implements the Diffie-Hellman ratchet that layers on top of
 * the symmetric chain ratchet in crypto.c.  Together they form a "Double
 * Ratchet" — the same architecture Signal uses.
 *
 * WHY TWO RATCHETS?
 *
 * The symmetric ratchet (chain_step in crypto.c) provides forward secrecy:
 * each message key is derived from the chain key, used once, and wiped.
 * A compromised key today cannot decrypt past messages.
 *
 * But the symmetric ratchet has a gap: if an attacker extracts the current
 * chain key from RAM, they can derive ALL future message keys in that
 * chain.  The chain only goes forward deterministically — there is no
 * fresh randomness to lock them out.
 *
 * The DH ratchet fixes this.  Each time the conversation direction switches
 * (Alice was receiving, now she sends), the sender:
 *   1. Generates a fresh X25519 keypair.
 *   2. Computes dh_secret = X25519(new_priv, peer's latest public key).
 *   3. Mixes dh_secret into the root key: new_root = KDF(root || dh_secret).
 *   4. Derives a new sending chain from new_root.
 *   5. Includes the new public key in the frame (FLAG_RATCHET).
 *
 * The receiver does the mirror operation: compute the same DH secret using
 * their own private key and the sender's new public key, then derive a new
 * receiving chain.
 *
 * After this step, the attacker's stolen chain key is useless — the new
 * chain depends on a DH secret they don't have (the sender's fresh
 * private key was just generated from the CSPRNG).
 *
 * WHEN DOES THE RATCHET TRIGGER?
 *
 * Only on direction switch: if your last action was receiving and you are
 * about to send, a DH ratchet step happens first.  If you send multiple
 * messages in a row, only the first one triggers a ratchet.  This matches
 * natural conversation flow and avoids unnecessary key generation.
 *
 * A misbehaving peer that sends a ratchet key on every frame is harmless —
 * each step is one X25519 + one BLAKE2b, and the root key advances correctly.
 *
 * SEQUENCE NUMBERS
 *
 * tx_seq and rx_seq continue incrementing across ratchet steps — they are
 * never reset.  This trivially guarantees (key, nonce) uniqueness.
 *
 * Read next: crypto.h (symmetric ratchet), protocol.h (frame format)
 */

#ifndef SIMPLECIPHER_RATCHET_H
#define SIMPLECIPHER_RATCHET_H

#include "crypto.h"

/* Initialize DH ratchet state after the initial key exchange.
 *
 * Called by session_init after deriving the root key.  Sets up the DH
 * keypair and peer's public key for the first ratchet step.
 *
 * The initiator does one immediate ratchet step: generates a fresh keypair,
 * mixes a new DH secret into the root key, and derives the sending chain.
 * This ensures the first message always carries a ratchet key, and both
 * sides start synchronized.
 *
 * The responder starts with need_send_ratchet=1, expecting the initiator's
 * ratchet key in the first frame.
 *
 * self_priv/self_pub are the HANDSHAKE keypair — used only to compute the
 * initial peer_dh and the initiator's first DH.  A fresh ratchet keypair
 * is generated immediately; the handshake private key is NOT retained. */
void ratchet_init(session_t *s, int we_init, const uint8_t self_priv[KEY], const uint8_t self_pub[KEY],
                  const uint8_t peer_pub[KEY]);

/* Prepare to send a frame.
 *
 * If need_send_ratchet is set (our last action was receiving), triggers a
 * DH ratchet step:
 *   - Generates a fresh X25519 keypair.
 *   - Computes dh_secret = X25519(new_priv, peer_dh).
 *   - Derives new root key and sending chain.
 *   - Copies our new public key into ratchet_pub for the caller to include
 *     in the frame (FLAG_RATCHET).
 *   - Clears need_send_ratchet.
 *
 * Returns 1 if a ratchet step was performed (caller must set FLAG_RATCHET
 * and include ratchet_pub in the frame), 0 if no ratchet was needed.
 *
 * NOTE: this mutates session state (root, dh_priv, dh_pub, tx) before the
 * frame is written to the network.  If the write fails, the session is in
 * an inconsistent state.  This is acceptable because SimpleCipher treats
 * any I/O failure as session-fatal — there is no retry or recovery. */
int ratchet_send(session_t *s, uint8_t ratchet_pub[KEY]);

/* Process an incoming ratchet key from a received frame.
 *
 * Called by frame_open when FLAG_RATCHET is set.  Performs the receiver's
 * half of the DH ratchet step:
 *   - Computes dh_secret = X25519(our dh_priv, peer's new public key).
 *   - Derives new root key and receiving chain.
 *   - Stores the peer's new public key as peer_dh.
 *   - Wipes all intermediates (dh_secret, ikm).
 *
 * After this, the receiving chain is keyed with fresh DH entropy that an
 * attacker who stole the old chain key cannot derive. */
void ratchet_receive(session_t *s, const uint8_t peer_new_pub[KEY]);

#endif /* SIMPLECIPHER_RATCHET_H */
