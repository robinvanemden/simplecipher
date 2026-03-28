/*
 * test_socks5_proxy.c — SOCKS5 proxy loopback integration test.
 *
 * Spins up a minimal SOCKS5 proxy, connects through it via
 * connect_socket_socks5(), performs a full handshake, and exchanges
 * an encrypted message.  Exercises the entire proxy path end-to-end.
 *
 * Separate binary from test_p2p to avoid dual-stack/state pollution
 * from the 600+ tests that run before it.
 *
 * Build:
 *   gcc -std=c23 -Isrc -Ilib -pthread -o tests/test_socks5_proxy \
 *       tests/test_socks5_proxy.c src/platform.c src/crypto.c \
 *       src/protocol.c src/ratchet.c src/network.c src/tui.c \
 *       src/cli.c lib/monocypher.c src/tui_posix.c src/cli_posix.c
 */

#include "platform.h"
#include "crypto.h"
#include "protocol.h"
#include "ratchet.h"
#include "network.h"

#include <pthread.h>
/* REQUIRE() is disabled by -DNDEBUG; use a fatal check instead. */
#define REQUIRE(expr)                                                                                                  \
    do {                                                                                                               \
        if (!(expr)) {                                                                                                 \
            fprintf(stderr, "FATAL: %s failed at %s:%d\n", #expr, __FILE__, __LINE__);                                 \
            _exit(1);                                                                                                  \
        }                                                                                                              \
    } while (0)

static int g_pass = 0, g_fail = 0;
#define TEST(desc, expr)                                                                                               \
    do {                                                                                                               \
        if (expr) {                                                                                                    \
            printf("  PASS: %s\n", desc);                                                                              \
            g_pass++;                                                                                                  \
        } else {                                                                                                       \
            printf("  FAIL: %s\n", desc);                                                                              \
            g_fail++;                                                                                                  \
        }                                                                                                              \
    } while (0)

/* ---- Mini SOCKS5 proxy -------------------------------------------------- */

static void *mini_socks5_proxy(void *arg) {
    int srv    = *(int *)arg;
    int client = accept(srv, NULL, NULL);
    if (client < 0) return NULL;

    char buf[4096];

    /* Phase 1: greeting */
    if (recv(client, buf, 3, 0) != 3 || buf[0] != 5) goto done;
    char reply1[2] = {0x05, 0x00};
    send(client, reply1, 2, 0);

    /* Phase 2: CONNECT request */
    uint8_t hdr[4];
    if (recv(client, (char *)hdr, 4, 0) != 4) goto done;
    uint8_t atyp = hdr[3];

    int target_fd = -1;
    if (atyp == 0x01) { /* IPv4 */
        uint8_t addr[6];
        if (recv(client, (char *)addr, 6, 0) != 6) goto done;
        struct sockaddr_in sa = {.sin_family = AF_INET};
        memcpy(&sa.sin_addr, addr, 4);
        memcpy(&sa.sin_port, addr + 4, 2);
        target_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (target_fd < 0 || connect(target_fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
            char fail[10] = {0x05, 0x01};
            send(client, fail, 10, 0);
            if (target_fd >= 0) close(target_fd);
            goto done;
        }
    } else if (atyp == 0x03) { /* Domain */
        uint8_t dlen;
        if (recv(client, (char *)&dlen, 1, 0) != 1) goto done;
        char host[256] = {0};
        if (recv(client, host, dlen, 0) != dlen) goto done;
        uint8_t port_bytes[2];
        if (recv(client, (char *)port_bytes, 2, 0) != 2) goto done;
        char port_str[8];
        snprintf(port_str, sizeof port_str, "%d", (port_bytes[0] << 8) | port_bytes[1]);

        struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *res;
        if (getaddrinfo(host, port_str, &hints, &res) != 0) {
            char fail[10] = {0x05, 0x04};
            send(client, fail, 10, 0);
            goto done;
        }
        target_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        int rc    = (target_fd >= 0) ? connect(target_fd, res->ai_addr, (socklen_t)res->ai_addrlen) : -1;
        freeaddrinfo(res);
        if (rc != 0) {
            char fail[10] = {0x05, 0x05};
            send(client, fail, 10, 0);
            if (target_fd >= 0) close(target_fd);
            goto done;
        }
    } else {
        char fail[10] = {0x05, 0x08};
        send(client, fail, 10, 0);
        goto done;
    }

    /* Success reply */
    {
        char ok[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send(client, ok, 10, 0);
    }

    /* Relay loop */
    for (;;) {
        struct pollfd fds[2] = {{client, POLLIN, 0}, {target_fd, POLLIN, 0}};
        if (poll(fds, 2, 10000) <= 0) break;
        if (fds[0].revents & (POLLIN | POLLHUP)) {
            ssize_t n = recv(client, buf, sizeof buf, 0);
            if (n <= 0) break;
            send(target_fd, buf, (size_t)n, 0);
        }
        if (fds[1].revents & (POLLIN | POLLHUP)) {
            ssize_t n = recv(target_fd, buf, sizeof buf, 0);
            if (n <= 0) break;
            send(client, buf, (size_t)n, 0);
        }
    }
    close(target_fd);

done:
    close(client);
    return NULL;
}

/* ---- Server peer thread ------------------------------------------------- */

typedef struct {
    int       listen_fd;
    session_t sess;
    uint8_t   sas_key[KEY];
    socket_t  fd;
    int       ok;
} server_ctx;

static void *server_thread(void *arg) {
    server_ctx *ctx = (server_ctx *)arg;
    ctx->ok         = 0;
    ctx->fd         = accept(ctx->listen_fd, NULL, NULL);
    if (ctx->fd == INVALID_SOCK) return NULL;
    set_sock_opts(ctx->fd);
    set_sock_timeout(ctx->fd, 10);

    uint8_t priv[KEY], pub[KEY], peer_pub[KEY];
    uint8_t commit_self[KEY], commit_peer[KEY];
    gen_keypair(priv, pub);
    uint8_t self_nonce[KEY], peer_nonce[KEY];
    fill_random(self_nonce, KEY);
    make_commit(commit_self, pub, self_nonce);

    uint8_t out1[1 + KEY + KEY], in1[1 + KEY + KEY];
    out1[0] = (uint8_t)PROTOCOL_VERSION;
    memcpy(out1 + 1, commit_self, KEY);
    memcpy(out1 + 1 + KEY, self_nonce, KEY);
    if (exchange(ctx->fd, 0, out1, sizeof out1, in1, sizeof in1) != 0) goto done;
    memcpy(commit_peer, in1 + 1, KEY);
    memcpy(peer_nonce, in1 + 1 + KEY, KEY);
    if (exchange(ctx->fd, 0, pub, KEY, peer_pub, KEY) != 0) goto done;
    if (in1[0] != PROTOCOL_VERSION) goto done;
    if (!verify_commit(commit_peer, peer_pub, peer_nonce)) goto done;
    if (session_init(&ctx->sess, 0, priv, pub, peer_pub, self_nonce, peer_nonce, ctx->sas_key) != 0) goto done;
    ctx->ok = 1;
done:
    crypto_wipe(priv, sizeof priv);
    crypto_wipe(commit_self, sizeof commit_self);
    crypto_wipe(commit_peer, sizeof commit_peer);
    return NULL;
}

/* ---- Main --------------------------------------------------------------- */

int main(void) {
    printf("SOCKS5 Proxy Loopback Test\n");
    printf("==========================\n\n");

    plat_init();
    g_running = 1;

    /* Start mini SOCKS5 proxy */
    int proxy_srv = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(proxy_srv >= 0);
    int one = 1;
    setsockopt(proxy_srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in pa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    REQUIRE(bind(proxy_srv, (struct sockaddr *)&pa, sizeof pa) == 0);
    REQUIRE(listen(proxy_srv, 1) == 0);
    socklen_t palen = sizeof pa;
    getsockname(proxy_srv, (struct sockaddr *)&pa, &palen);
    char proxy_port[8];
    snprintf(proxy_port, sizeof proxy_port, "%d", ntohs(pa.sin_port));

    pthread_t proxy_tid;
    pthread_create(&proxy_tid, NULL, mini_socks5_proxy, &proxy_srv);

    /* Start target listener */
    int target_srv = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(target_srv >= 0);
    setsockopt(target_srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in ta = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    REQUIRE(bind(target_srv, (struct sockaddr *)&ta, sizeof ta) == 0);
    REQUIRE(listen(target_srv, 1) == 0);
    socklen_t talen = sizeof ta;
    getsockname(target_srv, (struct sockaddr *)&ta, &talen);
    char target_port[8];
    snprintf(target_port, sizeof target_port, "%d", ntohs(ta.sin_port));

    /* Server handshake thread */
    server_ctx srv = {.listen_fd = target_srv, .fd = INVALID_SOCK, .ok = 0};
    pthread_t  srv_tid;
    pthread_create(&srv_tid, NULL, server_thread, &srv);

    /* Small delay for threads to enter accept() */
    struct timespec ts = {0, 100000000};
    nanosleep(&ts, NULL);

    /* Connect through SOCKS5 proxy to target */
    socket_t client = connect_socket_socks5("127.0.0.1", proxy_port, "127.0.0.1", target_port);
    TEST("SOCKS5 connect succeeded", client != INVALID_SOCK);

    if (client == INVALID_SOCK) {
        fprintf(stderr, "  connect_socket_socks5 failed — proxy=%s target=%s\n", proxy_port, target_port);
        close(target_srv);
        close(proxy_srv);
        pthread_join(proxy_tid, NULL);
        pthread_join(srv_tid, NULL);
        goto summary;
    }

    set_sock_opts(client);
    set_sock_timeout(client, 10);

    /* Client handshake */
    uint8_t priv[KEY], pub[KEY], peer_pub[KEY];
    uint8_t commit_self[KEY], commit_peer[KEY];
    gen_keypair(priv, pub);
    uint8_t s5_self_nonce[KEY], s5_peer_nonce[KEY];
    fill_random(s5_self_nonce, KEY);
    make_commit(commit_self, pub, s5_self_nonce);

    uint8_t out1[1 + KEY + KEY], in1[1 + KEY + KEY];
    out1[0] = (uint8_t)PROTOCOL_VERSION;
    memcpy(out1 + 1, commit_self, KEY);
    memcpy(out1 + 1 + KEY, s5_self_nonce, KEY);

    int hs_ok = (exchange(client, 1, out1, sizeof out1, in1, sizeof in1) == 0);
    memcpy(commit_peer, in1 + 1, KEY);
    memcpy(s5_peer_nonce, in1 + 1 + KEY, KEY);
    hs_ok = hs_ok && (exchange(client, 1, pub, KEY, peer_pub, KEY) == 0);
    hs_ok = hs_ok && (in1[0] == PROTOCOL_VERSION);
    hs_ok = hs_ok && verify_commit(commit_peer, peer_pub, s5_peer_nonce);
    TEST("client handshake", hs_ok);

    pthread_join(srv_tid, NULL);
    TEST("server handshake", srv.ok);

    if (hs_ok && srv.ok) {
        session_t sess_c;
        uint8_t   sas_c[KEY];
        TEST("session_init", session_init(&sess_c, 1, priv, pub, peer_pub, s5_self_nonce, s5_peer_nonce, sas_c) == 0);
        TEST("SAS match", memcmp(sas_c, srv.sas_key, KEY) == 0);

        /* Exchange a message through the proxy */
        uint8_t  frame[FRAME_SZ], next_tx[KEY], plain[MAX_MSG + 1];
        uint16_t plen;
        TEST("frame_build", frame_build(&sess_c, (const uint8_t *)"via socks5 proxy", 16, frame, next_tx) == 0);
        memcpy(sess_c.tx, next_tx, KEY);
        sess_c.tx_seq++;
        TEST("write through proxy", frame_send(client, frame, 0) == 0);
        TEST("read through proxy", frame_recv(srv.fd, frame, 0) == 0);
        plen = 0;
        TEST("frame_open", frame_open(&srv.sess, frame, plain, &plen) == 0);
        plain[plen] = '\0';
        TEST("message correct", strcmp((char *)plain, "via socks5 proxy") == 0);

        session_wipe(&sess_c);
        session_wipe(&srv.sess);
    }

    crypto_wipe(priv, sizeof priv);
    if (client != INVALID_SOCK) close_sock(client);
    if (srv.fd != INVALID_SOCK) close_sock(srv.fd);
    close(target_srv);
    close(proxy_srv);
    pthread_join(proxy_tid, NULL);

summary:
    printf("\n==========================\n");
    printf("Total: %d passed, %d failed\n", g_pass, g_fail);
    printf("==========================\n");
    return g_fail > 0 ? 1 : 0;
}
