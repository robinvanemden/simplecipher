/*
 * nb_io.c — Non-blocking frame I/O helpers
 *
 * Implements the state machine for incremental TCP frame read/write.
 * All functions are pure I/O + state management — no UI output.
 * Each chat loop (cli raw, cli cooked, tui) calls these helpers
 * and provides its own UI feedback around them.
 *
 * NOTE: nb_io_init, nb_io_wipe, nb_try_recv, nb_try_send are currently
 * defined in network.c (Task 3 will migrate them here).  This file
 * provides only the higher-level state machine helpers that are new.
 */

#include "nb_io.h"
/* nb_io.h already pulls in protocol.h (FRAME_TIMEOUT_S, FRAME_SZ, session_t).
 * We need frame_wire_build() from network.c, but network.h re-declares
 * nb_io_t and friends (Task 3 will remove them).  Forward-declare only
 * what we need to avoid the conflicting-types error. */
size_t frame_wire_build(uint8_t *wire, const uint8_t *frame);

#include <string.h>

/* ---- Inbound frame accumulation ---------------------------------------- */

int nb_io_accumulate(nb_io_t *io, socket_t fd) {
    int r = nb_try_recv(fd, io->in_wire + io->in_have,
                        io->in_need - io->in_have);
    if (r < 0) return NB_RECV_DISCONNECT;
    if (r == 0) return NB_RECV_INCOMPLETE;

    if (io->in_have == 0) io->in_start_ms = monotonic_ms();
    io->in_have += (size_t)r;

    /* Phase 1: pad_len byte received — compute full frame size. */
    if (io->in_have >= io->in_need && io->in_need == WIRE_HDR)
        io->in_need = WIRE_HDR + FRAME_SZ + (size_t)io->in_wire[0];

    /* Phase 2: full padded frame assembled. */
    if (io->in_have >= io->in_need && io->in_need > WIRE_HDR)
        return NB_RECV_FRAME;

    return NB_RECV_INCOMPLETE;
}

void nb_io_reset_recv(nb_io_t *io) {
    crypto_wipe(io->in_wire, sizeof io->in_wire);
    io->in_have     = 0;
    io->in_need     = WIRE_HDR;
    io->in_start_ms = 0;
}

/* ---- Outbound frame drain ---------------------------------------------- */

int nb_io_drain(nb_io_t *io, socket_t fd) {
    int s = nb_try_send(fd, io->out_wire + io->out_off,
                        io->out_len - io->out_off);
    if (s < 0) return NB_SEND_ERROR;
    if (s > 0) io->out_off += (size_t)s;
    return (io->out_off >= io->out_len) ? NB_SEND_COMPLETE : NB_SEND_INCOMPLETE;
}

/* ---- Send lifecycle ---------------------------------------------------- */

int nb_io_start_send(nb_io_t *io, session_t *sess, socket_t fd,
                     const uint8_t *payload, uint16_t len,
                     const char *msg_text) {
    uint8_t out_frame[FRAME_SZ];
    if (frame_build(sess, payload, len, out_frame, io->out_next_tx) != 0) {
        crypto_wipe(out_frame, sizeof out_frame);
        return -1;
    }
    io->out_len = frame_wire_build(io->out_wire, out_frame);
    crypto_wipe(out_frame, sizeof out_frame);

    io->out_off      = 0;
    io->out_active   = 1;
    io->out_start_ms = monotonic_ms();

    if (msg_text && msg_text[0]) {
        size_t tlen = strlen(msg_text);
        if (tlen > MAX_MSG) tlen = MAX_MSG;
        memcpy(io->out_text, msg_text, tlen);
        io->out_text[tlen] = '\0';
    } else {
        io->out_text[0] = '\0';
    }

    /* Try to send immediately — often completes in one call. */
    int s = nb_try_send(fd, io->out_wire, io->out_len);
    if (s < 0) return -1;
    if (s > 0) io->out_off += (size_t)s;
    return 0;
}

void nb_io_complete_send(nb_io_t *io, session_t *sess) {
    memcpy(sess->tx, io->out_next_tx, KEY);
    sess->tx_seq++;
    io->out_active = 0;
    crypto_wipe(io->out_wire, sizeof io->out_wire);
    crypto_wipe(io->out_next_tx, sizeof io->out_next_tx);
    crypto_wipe(io->out_text, sizeof io->out_text);
}

/* ---- Deadline checks --------------------------------------------------- */

int nb_io_recv_deadline_expired(const nb_io_t *io) {
    return io->in_have > 0 &&
           (monotonic_ms() - io->in_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000;
}

int nb_io_send_deadline_expired(const nb_io_t *io) {
    return io->out_active &&
           (monotonic_ms() - io->out_start_ms) > (uint64_t)FRAME_TIMEOUT_S * 1000;
}
