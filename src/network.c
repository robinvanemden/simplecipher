/*
 * network.c — TCP networking implementation for SimpleCipher
 *
 * Implements socket timeout/options, exact-byte I/O, the simultaneous
 * exchange helper, connect/listen setup, and local IP enumeration as
 * declared in network.h.
 */

#include "network.h"

/* ---- network I/O -------------------------------------------------------- */

/* Set a receive/send timeout of 'secs' seconds on the socket.
 * Used during the handshake to disconnect a stalled peer automatically.
 * Pass secs=0 to remove the timeout after the handshake completes.
 *
 * We warn (not abort) on failure: the session still works, but without
 * the timeout a stalling peer can block us indefinitely.  In practice
 * SO_RCVTIMEO fails only on very unusual socket types. */
void set_sock_timeout(socket_t fd, int secs){
#if defined(_WIN32) || defined(_WIN64)
    DWORD ms = (DWORD)(secs * 1000);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ms, sizeof ms) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&ms, sizeof ms) != 0)
        fprintf(stderr, "[warn] could not set socket timeout -- "
                "a stalling peer may block indefinitely\n");
#else
    struct timeval tv = { secs, 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) != 0)
        fprintf(stderr, "[warn] could not set socket timeout -- "
                "a stalling peer may block indefinitely\n");
#endif
}

/* Enable TCP keepalives and disable Nagle's algorithm on the socket.
 *
 * SO_KEEPALIVE: the OS probes a silent peer after idle time and closes
 * the socket if there is no response, waking poll() for a clean exit.
 *
 * TCP_NODELAY: disables Nagle's algorithm, which would otherwise buffer
 * small writes for up to ~200ms waiting to coalesce them.  Our frames are
 * always exactly 512 bytes so Nagle rarely fires, but disabling it removes
 * any latency on the rare case it does and is standard for interactive tools. */
void set_sock_opts(socket_t fd){
    int one = 1;
    setsockopt(fd, SOL_SOCKET,   SO_KEEPALIVE,  (const char*)&one, sizeof one);
    setsockopt(fd, IPPROTO_TCP,  TCP_NODELAY,   (const char*)&one, sizeof one);
}

/* Read exactly n bytes from fd into buf, looping on partial reads.
 * TCP is a stream: a single recv() may return fewer bytes than asked for.
 * Returns 0 when all n bytes are in buf, -1 on error or peer close. */
[[nodiscard]] int read_exact(socket_t fd, void *buf, size_t n){
    size_t done = 0;
    while (done < n){
#ifdef _WIN32
        int r = recv(fd, (char*)buf + done, (int)(n - done), 0);
        if (r <= 0) return -1;
#else
        ssize_t r = recv(fd, (char*)buf + done, n - done, 0);
        if (r < 0){ if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
#endif
        done += (size_t)r;
    }
    return 0;
}

/* Write exactly n bytes from buf to fd, looping on partial writes.
 * MSG_NOSIGNAL suppresses SIGPIPE on Linux when the peer closes. */
[[nodiscard]] int write_exact(socket_t fd, const void *buf, size_t n){
    size_t done = 0;
    while (done < n){
#ifdef _WIN32
        int r = send(fd, (const char*)buf + done, (int)(n - done), 0);
        if (r <= 0) return -1;
#else
        ssize_t r = send(fd, (const char*)buf + done, n - done, MSG_NOSIGNAL);
        if (r < 0){ if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
#endif
        done += (size_t)r;
    }
    return 0;
}

/* Exchange one value simultaneously with the peer.
 * The initiator sends first to avoid both sides waiting for each other. */
[[nodiscard]] int exchange(socket_t fd, int we_init,
                           const uint8_t *out, size_t out_n,
                           uint8_t *in,        size_t in_n){
    if (we_init){
        if (write_exact(fd, out, out_n) != 0) return -1;
        if (read_exact (fd, in,  in_n)  != 0) return -1;
    } else {
        if (read_exact (fd, in,  in_n)  != 0) return -1;
        if (write_exact(fd, out, out_n) != 0) return -1;
    }
    return 0;
}

/* Print non-loopback IP addresses so the user can tell their peer where
 * to connect.  Skips link-local (169.254.x.x, fe80::) and loopback. */
void print_local_ips(const char *port){
#if defined(_WIN32) || defined(_WIN64)
    ULONG bufsz = 15000;
    IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)malloc(bufsz);
    if (!addrs) return;
    DWORD rv = GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_SKIP_DNS_SERVER, nullptr, addrs, &bufsz);
    if (rv != ERROR_SUCCESS){ free(addrs); return; }
    int n = 0;
    for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next){
        if (a->OperStatus != IfOperStatusUp) continue;
        for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next){
            struct sockaddr *sa = u->Address.lpSockaddr;
            char ip[INET6_ADDRSTRLEN];
            if (sa->sa_family == AF_INET){
                struct sockaddr_in *s4 = (struct sockaddr_in *)sa;
                if ((ntohl(s4->sin_addr.s_addr) >> 24) == 127) continue;
                if ((ntohl(s4->sin_addr.s_addr) >> 16) == 0xa9fe) continue;
                inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip);
            } else if (sa->sa_family == AF_INET6){
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)sa;
                if (IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr)) continue;
                if (IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) continue;
                inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof ip);
            } else continue;
            printf("    simplecipher connect %s %s\n", ip, port);
            n++;
        }
    }
    free(addrs);
    if (!n) printf("  (no network interfaces found)\n");
#else
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa) != 0) return;
    int n = 0;
    for (p = ifa; p; p = p->ifa_next){
        if (!p->ifa_addr) continue;
        char ip[INET6_ADDRSTRLEN];
        if (p->ifa_addr->sa_family == AF_INET){
            struct sockaddr_in *s4 = (struct sockaddr_in *)p->ifa_addr;
            if (ntohl(s4->sin_addr.s_addr) >> 24 == 127) continue;
            if ((ntohl(s4->sin_addr.s_addr) >> 16) == 0xa9fe) continue;
            inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip);
        } else if (p->ifa_addr->sa_family == AF_INET6){
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)p->ifa_addr;
            if (IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr)) continue;
            if (IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) continue;
            inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof ip);
        } else continue;
        printf("    simplecipher connect %s %s\n", ip, port);
        n++;
    }
    freeifaddrs(ifa);
    if (!n) printf("  (no network interfaces found)\n");
#endif
}

/* Collect non-loopback IPv4 addresses into a buffer.
 * Returns the number of addresses found. */
int get_local_ips(char *buf, size_t buf_sz){
    int n = 0;
    size_t off = 0;
    if (!buf || buf_sz == 0) return 0;
    buf[0] = '\0';
#if defined(_WIN32) || defined(_WIN64)
    ULONG sz = 15000;
    IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)malloc(sz);
    if (!addrs) return 0;
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
            GAA_FLAG_SKIP_DNS_SERVER, nullptr, addrs, &sz) != ERROR_SUCCESS){
        free(addrs); return 0;
    }
    for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next){
        if (a->OperStatus != IfOperStatusUp) continue;
        for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next){
            struct sockaddr *sa = u->Address.lpSockaddr;
            if (sa->sa_family != AF_INET) continue;
            struct sockaddr_in *s4 = (struct sockaddr_in *)sa;
            if ((ntohl(s4->sin_addr.s_addr) >> 24) == 127) continue;
            if ((ntohl(s4->sin_addr.s_addr) >> 16) == 0xa9fe) continue;
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip);
            int w = snprintf(buf + off, buf_sz - off, "%s%s", n ? "\n" : "", ip);
            if (w > 0){
                /* snprintf returns the would-have-written length even when
                 * truncated.  Clamp off to the buffer boundary so the next
                 * iteration does not write past the end of buf. */
                off += (size_t)w;
                if (off >= buf_sz) off = buf_sz - 1;
            }
            n++;
        }
    }
    free(addrs);
#else
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa) != 0) return 0;
    for (p = ifa; p; p = p->ifa_next){
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        struct sockaddr_in *s4 = (struct sockaddr_in *)p->ifa_addr;
        if (ntohl(s4->sin_addr.s_addr) >> 24 == 127) continue;
        if ((ntohl(s4->sin_addr.s_addr) >> 16) == 0xa9fe) continue;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip);
        int w = snprintf(buf + off, buf_sz - off, "%s%s", n ? "\n" : "", ip);
        if (w > 0) off += (size_t)w;
        n++;
    }
    freeifaddrs(ifa);
#endif
    return n;
}

/* Connect to host:port, trying all addresses getaddrinfo returns.
 * Returns the connected socket, or INVALID_SOCK on failure. */
[[nodiscard]] socket_t connect_socket(const char *host, const char *port){
    struct addrinfo hints, *res, *p;
    socket_t fd = INVALID_SOCK;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    if (getaddrinfo(host, port, &hints, &res) != 0) return INVALID_SOCK;
    for (p = res; p; p = p->ai_next){
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == INVALID_SOCK) continue;
#if defined(_WIN32) || defined(_WIN64)
        g_interrupt_sock = fd;
#endif
        if (connect(fd, p->ai_addr, (socklen_t)p->ai_addrlen) == 0) break;
#if defined(_WIN32) || defined(_WIN64)
        g_interrupt_sock = INVALID_SOCKET;
#endif
        close_sock(fd); fd = INVALID_SOCK;
    }
    freeaddrinfo(res);
#if defined(_WIN32) || defined(_WIN64)
    g_interrupt_sock = INVALID_SOCKET;
#endif
    if (fd != INVALID_SOCK) set_sock_opts(fd);
    return fd;
}

/* Bind to port, accept exactly one connection, close the listener.
 * One peer only -- this is not a server.
 * SO_REUSEADDR avoids "address already in use" on quick restarts.
 * IPV6_V6ONLY=0 accepts both IPv4 and IPv6 on dual-stack systems. */
[[nodiscard]] socket_t listen_socket(const char *port){
    struct addrinfo hints, *res, *p;
    socket_t srv = INVALID_SOCK, fd = INVALID_SOCK;
    int one = 1;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_flags    = AI_PASSIVE;
    if (getaddrinfo(nullptr, port, &hints, &res) != 0) return INVALID_SOCK;
    for (p = res; p; p = p->ai_next){
        srv = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (srv == INVALID_SOCK) continue;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof one);
#ifdef IPV6_V6ONLY
        if (p->ai_family == AF_INET6){
            int off = 0;
            setsockopt(srv, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof off);
        }
#endif
        if (bind(srv, p->ai_addr, (socklen_t)p->ai_addrlen) == 0
            && listen(srv, 1) == 0) break;
        close_sock(srv); srv = INVALID_SOCK;
    }
    freeaddrinfo(res);
    if (srv == INVALID_SOCK) return INVALID_SOCK;
    /* Retry accept() on EINTR (e.g. Ctrl+C while waiting for a peer)
     * so the signal handler can set g_running=0 and we exit cleanly
     * rather than showing a confusing "listen/accept failed" error.
     *
     * On Windows, the console control handler runs in a separate thread
     * and cannot interrupt accept().  We register the listening socket
     * in g_interrupt_sock so the handler can closesocket() it, which
     * causes accept() to return WSAENOTSOCK or WSAEINTR. */
#if defined(_WIN32) || defined(_WIN64)
    g_interrupt_sock = srv;
#endif
    do { fd = accept(srv, nullptr, nullptr); }
    while (fd == INVALID_SOCK && errno == EINTR && g_running);
#if defined(_WIN32) || defined(_WIN64)
    g_interrupt_sock = INVALID_SOCKET;
#endif
    close_sock(srv);
    if (fd != INVALID_SOCK) set_sock_opts(fd);
    return fd;
}

/* Like listen_socket, but calls on_idle() every ~250ms while waiting.
 * This lets TUI mode handle terminal resize events during the wait.
 * Uses select() with a short timeout instead of blocking accept(). */
[[nodiscard]] socket_t listen_socket_cb(const char *port,
                                        void (*on_idle)(void *ctx), void *ctx){
    struct addrinfo hints, *res, *p;
    socket_t srv = INVALID_SOCK, fd = INVALID_SOCK;
    int one = 1;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_flags    = AI_PASSIVE;
    if (getaddrinfo(nullptr, port, &hints, &res) != 0) return INVALID_SOCK;
    for (p = res; p; p = p->ai_next){
        srv = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (srv == INVALID_SOCK) continue;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof one);
#ifdef IPV6_V6ONLY
        if (p->ai_family == AF_INET6){
            int off = 0;
            setsockopt(srv, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof off);
        }
#endif
        if (bind(srv, p->ai_addr, (socklen_t)p->ai_addrlen) == 0
            && listen(srv, 1) == 0) break;
        close_sock(srv); srv = INVALID_SOCK;
    }
    freeaddrinfo(res);
    if (srv == INVALID_SOCK) return INVALID_SOCK;

#if defined(_WIN32) || defined(_WIN64)
    g_interrupt_sock = srv;
#endif

    /* Poll accept() with a 250ms timeout, calling on_idle() between rounds.
     * On POSIX, select() returns on EINTR from signals (SIGWINCH for resize,
     * SIGINT for Ctrl+C).  On Windows, g_interrupt_sock lets the console
     * handler break us out of select() by closing the socket. */
    while (g_running){
        fd_set rfds;
        struct timeval tv;
        int sr;

        FD_ZERO(&rfds);
        FD_SET(srv, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 250000;  /* 250ms */

        sr = select((int)(srv + 1), &rfds, nullptr, nullptr, &tv);
        if (sr < 0){
#ifndef _WIN32
            if (errno == EINTR) { if (on_idle) on_idle(ctx); continue; }
#endif
            break;
        }
        if (sr == 0){ if (on_idle) on_idle(ctx); continue; }  /* timeout */
        fd = accept(srv, nullptr, nullptr);
        if (fd != INVALID_SOCK) break;
#ifndef _WIN32
        if (errno == EINTR) continue;
#endif
        break;
    }

#if defined(_WIN32) || defined(_WIN64)
    g_interrupt_sock = INVALID_SOCKET;
#endif
    close_sock(srv);
    if (fd != INVALID_SOCK) set_sock_opts(fd);
    return fd;
}
