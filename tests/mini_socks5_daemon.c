/*
 * mini_socks5_daemon.c — Minimal SOCKS5 proxy for emulator testing.
 *
 * Listens on 127.0.0.1:9050, accepts one client, performs SOCKS5
 * no-auth negotiation, connects to the requested target, and relays
 * bytes bidirectionally. Exits after the first session completes.
 *
 * Used by the Android emulator test to exercise the app's real
 * SOCKS5 path (Java UI → JNI → connect_socket_socks5 → this proxy
 * → simplecipher peer → handshake → SAS screen).
 *
 * Build (NDK for x86_64 Android):
 *   $CC -static -o mini_socks5_daemon mini_socks5_daemon.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>

/* TCP-correct exact-byte read/write — loops on partial returns. */
static int recv_exact(int fd, void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = recv(fd, (char *)buf + done, n - done, 0);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return -1; }
        done += (size_t)r;
    }
    return 0;
}
static int send_all(int fd, const void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = send(fd, (const char *)buf + done, n - done, 0);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return -1; }
        done += (size_t)r;
    }
    return 0;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(9050)
    };
    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0) {
        perror("bind 9050"); return 1;
    }
    listen(srv, 1);
    fprintf(stderr, "mini_socks5_daemon: listening on 127.0.0.1:9050\n");

    int client = accept(srv, NULL, NULL);
    close(srv); /* one session only */
    if (client < 0) { perror("accept"); return 1; }

    /* SOCKS5 greeting */
    char buf[4096];
    if (recv_exact(client, buf, 3) != 0 || buf[0] != 5) goto done;
    char reply1[2] = {5, 0};
    send_all(client, reply1, 2);

    /* SOCKS5 CONNECT request */
    unsigned char hdr[4];
    if (recv_exact(client, hdr, 4) != 0) goto done;
    int target_fd = -1;

    if (hdr[3] == 0x01) { /* IPv4 */
        unsigned char a[6];
        if (recv_exact(client, a, 6) != 0) goto done;
        struct sockaddr_in sa = {.sin_family = AF_INET};
        memcpy(&sa.sin_addr, a, 4);
        memcpy(&sa.sin_port, a + 4, 2);
        target_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (target_fd < 0 || connect(target_fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
            char fail[10] = {5, 1};
            send_all(client, fail, 10);
            if (target_fd >= 0) close(target_fd);
            goto done;
        }
    } else if (hdr[3] == 0x03) { /* Domain */
        unsigned char dlen;
        if (recv_exact(client, &dlen, 1) != 0) goto done;
        char host[256] = {0};
        if (recv_exact(client, host, dlen) != 0) goto done;
        unsigned char pb[2];
        if (recv_exact(client, pb, 2) != 0) goto done;
        char port_str[8];
        snprintf(port_str, sizeof port_str, "%d", (pb[0] << 8) | pb[1]);
        struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *res;
        if (getaddrinfo(host, port_str, &hints, &res) != 0) {
            char fail[10] = {5, 4};
            send_all(client, fail, 10);
            goto done;
        }
        target_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        int rc = (target_fd >= 0) ? connect(target_fd, res->ai_addr, (socklen_t)res->ai_addrlen) : -1;
        freeaddrinfo(res);
        if (rc != 0) {
            char fail[10] = {5, 5};
            send_all(client, fail, 10);
            if (target_fd >= 0) close(target_fd);
            goto done;
        }
    } else {
        char fail[10] = {5, 8};
        send_all(client, fail, 10);
        goto done;
    }

    /* Success */
    {
        char ok[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
        send_all(client, ok, 10);
    }

    /* Relay */
    for (;;) {
        struct pollfd fds[2] = {{client, POLLIN, 0}, {target_fd, POLLIN, 0}};
        if (poll(fds, 2, 30000) <= 0) break;
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
    fprintf(stderr, "mini_socks5_daemon: session complete\n");
    return 0;
}
