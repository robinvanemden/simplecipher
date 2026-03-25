/*
 * jni_bridge.c — Single-threaded native session for SimpleCipher Android.
 *
 * Architecture:
 *   Java calls nativeStart(mode, host, port, callback) which creates a
 *   pipe and spawns ONE pthread that owns ALL crypto, session, and socket
 *   state.  Java communicates with it by writing commands to the pipe via
 *   nativePostCommand().  Results come back through JNI callbacks on the
 *   NativeCallback interface.
 *
 * Why a single thread?
 *   The previous model spawned Java threads for connect, handshake, send,
 *   receive, and disconnect — all touching the same globals.  Even with a
 *   mutex, two send threads could read the same (chain key, seq) before
 *   either committed the update, reusing a (key, nonce) pair.  For
 *   XChaCha20-Poly1305 that completely breaks confidentiality.
 *
 *   A single thread with exclusive ownership of all crypto/session/socket
 *   state makes data races on security-critical paths structurally
 *   impossible — no mutex needed for the protocol itself.
 *
 *   A small number of lifecycle/control globals (pipe fd, listen socket,
 *   session-active flag, generation counter) are shared between the JNI
 *   calling thread and the session thread.  These use C11 atomics for
 *   formal thread safety.  They carry no crypto material.
 *
 * Fingerprint verification (optional):
 *   Before connecting, MainActivity can call nativeGenerateKey() to
 *   pre-generate an ephemeral keypair and display its fingerprint as a
 *   QR code or text.  The peer's fingerprint (scanned or typed) is stored
 *   via nativeSetPeerFingerprint().  Both are passed to the session thread
 *   through the thread_arg_t struct (globals wiped before thread spawn).
 *   After the key exchange, the peer's public key is hashed and compared
 *   against the expected fingerprint using ct_compare() (constant-time).
 *   On match, onPeerFingerprintReady(fp, true) fires and SAS is skipped.
 *   On mismatch, onHandshakeFailed() fires and the connection is torn down.
 *
 * Command protocol (pipe):
 *   [1 byte: cmd] [2 bytes: payload length, little-endian] [payload]
 *   All writes are < PIPE_BUF (4096) so they are atomic from any thread.
 *   The write end is O_NONBLOCK so the UI thread never stalls; if the
 *   pipe is full (session thread stuck in a socket write), the command
 *   is dropped and nativePostCommand() returns JNI_FALSE so Java can
 *   show the failure instead of a phantom "sent" message.
 *
 * CMD_SEND         = 0x01  (payload = UTF-8 message, max 486 bytes)
 * CMD_CONFIRM_SAS  = 0x02  (no payload)
 *
 * Session teardown uses nativeStop() — an out-of-band mechanism that
 * directly closes the pipe write end, shuts down the session socket,
 * and closes the listen socket.  This is non-droppable: it works even
 * when the pipe is full or the session thread is blocked in I/O.
 * CMD_QUIT (0x03) is still handled in the event loop for robustness
 * but is no longer the primary quit path.
 *
 * How nativeStop() unblocks each phase:
 *   Connect:  poll() on pipe fd returns POLLHUP → abort connect
 *   Listen:   select() marks pipe fd readable (EOF) + close(listen_sock)
 *             makes select() return on srv → accept() fails → break
 *   SAS wait: pipe_read_exact() returns EOF → goto cleanup
 *   Chat:     poll() on pipe fd returns POLLHUP → pipe_read_exact()
 *             returns EOF → break;  shutdown(sock) also unblocks any
 *             in-progress read_exact() on the socket side
 */

#include "platform.h"
#include "crypto.h"
#include "protocol.h"
#include "network.h"

#include <jni.h>
#include <sys/select.h>
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>  /* pipe, read, write, close */
#include <fcntl.h>   /* fcntl, O_NONBLOCK */
#include <poll.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <stdatomic.h>

/* ---- Logging ------------------------------------------------------------ */

#define TAG "SimpleCipher"
#ifdef NDEBUG
/* Release: suppress all logging to prevent leaking sensitive data to logcat */
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#endif

/* ---- Command bytes ------------------------------------------------------ */

#define CMD_SEND        0x01
#define CMD_CONFIRM_SAS 0x02
#define CMD_QUIT        0x03

/* ---- Globals ------------------------------------------------------------ */

/* Cached JavaVM pointer — set once in JNI_OnLoad, never changes.
 * Needed to attach the native thread to the JVM so it can call back. */
static JavaVM *g_jvm = NULL;

/* Write end of the command pipe — exclusively owned by the Java side.
 * Only nativeStart() sets it (after pipe()), only nativeStart() closes it
 * (when starting a new session or on error), and only nativePostCommand()
 * reads it for writing commands.  The session thread never touches this fd;
 * it only owns the read end (pipe_rd).  This single-owner design prevents
 * stale-fd and double-close bugs that arise when the same fd number is
 * closed by two different code paths.
 *
 * Pipe writes are atomic because the command header + payload is always
 * < PIPE_BUF (4096 bytes).
 *
 * All cross-thread globals below use C11 atomics for formal thread safety.
 * The crypto/session/socket state itself is still single-threaded (owned
 * exclusively by the session pthread), but these lifecycle/control globals
 * are shared between the JNI calling thread and the session thread. */
static _Atomic int g_pipe_wr = -1;

/* Listen socket — set while the native thread is blocked in accept().
 * nativeStop() closes this to unblock accept(). */
static _Atomic socket_t g_listen_sock = INVALID_SOCK;

/* Session socket — set by the session thread after connect/accept.
 * nativeStop() calls shutdown() on this to unblock any stuck
 * read_exact()/write_exact() in the session thread.  The thread
 * still owns the fd for close(). */
static _Atomic socket_t g_session_sock = INVALID_SOCK;

/* Session thread handle — used to join the thread before starting a new
 * session, ensuring the previous socket is fully closed. */
static pthread_t g_session_thread;
static _Atomic int g_session_active = 0;

/* Session generation counter.  Incremented by nativeStart() each time a
 * new session is spawned.  The session thread stores its own generation
 * at birth and only clears g_session_active if the generation still
 * matches — preventing a stale thread from marking a newer session inactive. */
static _Atomic int g_session_gen = 0;

/* ---- Pre-generated key (set by MainActivity before nativeStart) --------- */

static uint8_t  g_prekey_priv[KEY];
static uint8_t  g_prekey_pub[KEY];
static int      g_prekey_valid = 0;

static uint8_t  g_peer_fp[8];
static int      g_peer_fp_valid = 0;

/* ---- Thread argument struct --------------------------------------------- */

/* Everything the session thread needs, passed as pthread arg.
 * The thread copies what it needs and frees the struct immediately. */
typedef struct {
    int       mode;         /* 0 = listen, 1 = connect                    */
    char     *host;         /* strdup'd host string (connect only), or NULL */
    int       port;
    char     *socks5_host;  /* SOCKS5 proxy host (e.g. "127.0.0.1"), or NULL */
    char     *socks5_port;  /* SOCKS5 proxy port (e.g. "9050"), or NULL      */
    int       pipe_rd;      /* read end of command pipe                    */
    int       gen;          /* session generation (for stale-thread guard)  */
    jobject   callback;     /* JNI global ref to NativeCallback            */

    /* Pre-resolved JNI method IDs — looked up on the calling thread
     * so the native thread doesn't need to do class lookups. */
    jmethodID mid_onConnected;
    jmethodID mid_onConnectionFailed;
    jmethodID mid_onSasReady;
    jmethodID mid_onHandshakeFailed;
    jmethodID mid_onMessageReceived;
    jmethodID mid_onSendResult;
    jmethodID mid_onDisconnected;

    /* Pre-generated keypair (copied from globals, which are wiped) */
    uint8_t   prekey_priv[KEY];
    uint8_t   prekey_pub[KEY];
    int       has_prekey;

    /* Expected peer fingerprint (8 raw bytes from globals) */
    uint8_t   peer_fp[8];
    int       has_peer_fp;

    /* 8th callback method ID */
    jmethodID mid_onPeerFingerprintReady;
} thread_arg_t;

/* ---- Helper: read exactly n bytes from a file descriptor ---------------- */

/* Like read_exact() for sockets, but for the pipe fd.
 * Returns 0 on success, -1 on error/EOF. */
static int pipe_read_exact(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) return -1;  /* EOF or error */
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

/* ct_compare is declared in crypto.h — shared with desktop code and
 * testable by the timing verification suite (dudect/timecop). */

/* Parse a fingerprint string "XXXX-XXXX-XXXX-XXXX" into 8 raw bytes.
 * Accepts uppercase, lowercase, and mixed-case hex.  Dashes are skipped.
 * Returns 0 on success, -1 if the string is malformed or wrong length.
 * Used to convert the scanned/typed peer fingerprint for comparison
 * against the hash of the peer's actual public key after handshake. */
static int parse_fingerprint(uint8_t out[8], const char *s) {
    uint8_t buf[8];
    int bi = 0;
    for (int i = 0; s[i] && bi < 8; i++) {
        char c = s[i];
        if (c == '-') continue;
        int hi, lo;
        if      (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else return -1;
        i++;
        if (!s[i]) return -1;
        c = s[i];
        if      (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else return -1;
        buf[bi++] = (uint8_t)((hi << 4) | lo);
    }
    if (bi != 8) return -1;
    memcpy(out, buf, 8);
    return 0;
}

/* ---- Session thread ----------------------------------------------------- */

/* Safe JNI callback: call a void method and check for exceptions.
 * If NewStringUTF failed (returned NULL) or the callback threw,
 * clear the exception so the native thread doesn't crash on the
 * next JNI call.  Returns 0 on success, -1 on exception. */
static int jni_callback_ok(JNIEnv *env) {
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        LOGE("JNI exception in callback — session state may be stale");
        return -1;
    }
    return 0;
}

/* Convenience: create a Java string, call a void(String) callback,
 * delete the local ref, and check for exceptions.  If NewStringUTF
 * returns NULL (OOM) or the callback throws, returns -1.  label is
 * used only for logging on failure. */
static int jni_call_str(JNIEnv *env, jobject cb, jmethodID mid,
                         const char *str, const char *label) {
    jstring jstr = (*env)->NewStringUTF(env, str);
    if (!jstr) {
        LOGE("NewStringUTF(%s) failed", label);
        return -1;
    }
    (*env)->CallVoidMethod(env, cb, mid, jstr);
    (*env)->DeleteLocalRef(env, jstr);
    return jni_callback_ok(env);
}

static void *session_thread(void *arg) {
    thread_arg_t *ta = (thread_arg_t *)arg;

    /* Copy everything we need from the arg struct, then free it.
     * This avoids a dangling pointer if the caller's stack unwinds. */
    int       mode        = ta->mode;
    char     *host        = ta->host;        /* we own this (strdup'd) */
    int       port        = ta->port;
    char     *socks5_host = ta->socks5_host; /* strdup'd or NULL */
    char     *socks5_port = ta->socks5_port; /* strdup'd or NULL */
    int       pipe_rd     = ta->pipe_rd;
    int       my_gen  = ta->gen;        /* session generation at birth */
    jobject   cb      = ta->callback;   /* global ref — we delete on exit */

    jmethodID mid_onConnected        = ta->mid_onConnected;
    jmethodID mid_onConnectionFailed = ta->mid_onConnectionFailed;
    jmethodID mid_onSasReady         = ta->mid_onSasReady;
    jmethodID mid_onHandshakeFailed  = ta->mid_onHandshakeFailed;
    jmethodID mid_onMessageReceived  = ta->mid_onMessageReceived;
    jmethodID mid_onSendResult       = ta->mid_onSendResult;
    jmethodID mid_onDisconnected     = ta->mid_onDisconnected;
    jmethodID mid_onPeerFingerprintReady = ta->mid_onPeerFingerprintReady;

    /* Pre-generated keypair: if the user expanded the fingerprint panel
     * on the connect screen, MainActivity called nativeGenerateKey() and
     * the key was copied into the thread arg by nativeStart().  We move
     * it to the stack and wipe the arg copy immediately. */
    int       has_prekey  = ta->has_prekey;
    uint8_t   prekey_priv[KEY], prekey_pub[KEY];
    if (has_prekey) {
        memcpy(prekey_priv, ta->prekey_priv, KEY);
        memcpy(prekey_pub,  ta->prekey_pub,  KEY);
        crypto_wipe(ta->prekey_priv, KEY);
        crypto_wipe(ta->prekey_pub,  KEY);
    }

    /* Expected peer fingerprint: if the user scanned or typed a peer
     * fingerprint, it was parsed to 8 raw bytes by nativeSetPeerFingerprint()
     * and copied into the thread arg by nativeStart().  After the handshake,
     * we compare this against the hash of the peer's actual public key. */
    int       has_peer_fp = ta->has_peer_fp;
    uint8_t   expected_peer_fp[8];
    if (has_peer_fp) {
        memcpy(expected_peer_fp, ta->peer_fp, 8);
        crypto_wipe(ta->peer_fp, 8);
    }

    free(ta);
    ta = NULL;

    /* Attach this thread to the JVM so we can make JNI callbacks. */
    JNIEnv *env = NULL;
    if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != JNI_OK) {
        LOGE("AttachCurrentThread failed");
        crypto_wipe(prekey_priv, sizeof prekey_priv);
        crypto_wipe(prekey_pub,  sizeof prekey_pub);
        crypto_wipe(expected_peer_fp, sizeof expected_peer_fp);
        free(host);
        free(socks5_host);
        free(socks5_port);
        close(pipe_rd);
        return NULL;
    }

    /* All session state lives on the stack — no globals, no races. */
    socket_t  fd       = INVALID_SOCK;
    session_t sess;
    int       we_init  = 0;
    uint8_t   self_priv[KEY], self_pub[KEY], peer_pub[KEY];

    memset(&sess, 0, sizeof sess);

    /* ================================================================
     * Phase 1: TCP connection
     * ================================================================ */

    char port_str[6];
    snprintf(port_str, sizeof port_str, "%d", port);

    if (mode == 1 && socks5_host) {
        /* SOCKS5 proxy connect (e.g. Tor via Orbot on 127.0.0.1:9050).
         *
         * The TCP connect to the proxy is to localhost, so it completes
         * instantly — no need for the non-blocking + poll() machinery.
         * The SOCKS5 negotiation is a few round-trips over localhost.
         * connect_socket_socks5() handles the full handshake. */
        LOGI("connecting via SOCKS5 %s:%s to %s:%s",
             socks5_host, socks5_port, host ? host : "(null)", port_str);

        fd = connect_socket_socks5(socks5_host, socks5_port, host, port_str);
        if (fd == INVALID_SOCK) {
            LOGE("SOCKS5 connect failed");
            jni_call_str(env, cb, mid_onConnectionFailed, "SOCKS5 proxy connect failed", "socks5_fail");
            goto cleanup;
        }
        set_sock_opts(fd);
        we_init = 1;
    } else if (mode == 1) {
        /* Direct connect mode — interruptible via nativeStop().
         *
         * We can't use connect_socket() directly because connect() can
         * block for up to 127 seconds (kernel SYN timeout) with no way
         * to interrupt it.  Instead, use non-blocking connect + poll()
         * on both the socket and the pipe so nativeStop()'s pipe close
         * (POLLHUP) is detected promptly. */
        LOGI("connecting to %s:%s", host ? host : "(null)", port_str);

        struct addrinfo hints, *res, *p;
        memset(&hints, 0, sizeof hints);
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family   = AF_UNSPEC;
        hints.ai_flags    = AI_NUMERICHOST; /* no DNS — numeric IPs only */
        if (getaddrinfo(host, port_str, &hints, &res) != 0) {
            LOGE("getaddrinfo failed for %s:%s (numeric IPs only)", host ? host : "(null)", port_str);
        } else {
            for (p = res; p; p = p->ai_next) {
                fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
                if (fd == INVALID_SOCK) continue;

                /* Set non-blocking for interruptible connect */
                int flags = fcntl((int)fd, F_GETFL);
                if (flags != -1) fcntl((int)fd, F_SETFL, flags | O_NONBLOCK);

                int rc = connect(fd, p->ai_addr, (socklen_t)p->ai_addrlen);
                if (rc == 0) {
                    /* Connected immediately — restore blocking */
                    if (flags != -1) fcntl((int)fd, F_SETFL, flags);
                    break;
                }
                if (errno != EINPROGRESS) {
                    close_sock(fd); fd = INVALID_SOCK;
                    continue;
                }

                /* Poll: wait for connect to complete or stop signal on pipe.
                 * nativeStop() closes the write end, producing POLLHUP (not
                 * POLLIN) on Linux — check both plus POLLERR for safety. */
                struct pollfd cfds[2];
                cfds[0].fd     = (int)fd;
                cfds[0].events = POLLOUT;
                cfds[1].fd     = pipe_rd;
                cfds[1].events = POLLIN;

                int connected = 0;
                int ret = poll(cfds, 2, HANDSHAKE_TIMEOUT_S * 1000);
                if (ret > 0 && (cfds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
                    /* nativeStop() closed the pipe (or CMD_QUIT fallback) — abort */
                    LOGI("quit received during connect");
                    close_sock(fd); fd = INVALID_SOCK;
                    freeaddrinfo(res);
                    jni_call_str(env, cb, mid_onDisconnected, "Session ended by user", "quit_connect");
                    goto cleanup;
                }
                if (ret > 0 && (cfds[0].revents & POLLOUT)) {
                    int err = 0;
                    socklen_t elen = sizeof err;
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                    if (err == 0) connected = 1;
                }

                /* Restore blocking mode */
                if (flags != -1) fcntl((int)fd, F_SETFL, flags);

                if (connected) break;
                close_sock(fd); fd = INVALID_SOCK;
            }
            freeaddrinfo(res);
            if (fd != INVALID_SOCK) set_sock_opts(fd);
        }
        we_init = 1;
    } else {
        /* Listen mode — interruptible via nativeStop().
         *
         * We can't use listen_socket() directly because it blocks in
         * accept() with no way to interrupt it.  Instead, use select()
         * with a 250ms timeout so nativeStop()'s pipe close or listen
         * socket close is detected promptly.  nativeStop() also closes
         * g_listen_sock, which makes select() return with srv readable
         * (accept then fails, breaking the loop).  This lets the user
         * press Back and immediately re-listen on the same port. */
        LOGI("listening on port %s", port_str);

        /* Bind and listen using the same setup as listen_socket but
         * keeping the server socket so we can select on it + the pipe. */
        struct addrinfo hints, *res, *p;
        socket_t srv = INVALID_SOCK;
        int one = 1;
        memset(&hints, 0, sizeof hints);
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family   = AF_UNSPEC;
        hints.ai_flags    = AI_PASSIVE;
        if (getaddrinfo(NULL, port_str, &hints, &res) != 0) {
            LOGE("getaddrinfo failed for port %s", port_str);
            jni_call_str(env, cb, mid_onConnectionFailed, "Listen failed (getaddrinfo)", "listen_gai");
            goto cleanup;
        }
        for (p = res; p; p = p->ai_next) {
            srv = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (srv == INVALID_SOCK) continue;
            setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
            if (bind(srv, p->ai_addr, (socklen_t)p->ai_addrlen) == 0
                && listen(srv, 1) == 0) break;
            close_sock(srv); srv = INVALID_SOCK;
        }
        freeaddrinfo(res);

        if (srv == INVALID_SOCK) {
            LOGE("bind/listen failed on port %s", port_str);
            jni_call_str(env, cb, mid_onConnectionFailed, "Listen failed (port in use?)", "listen_bind");
            goto cleanup;
        }

        /* Select: wait for a peer connection or nativeStop() signal.
         * When nativeStop() closes the pipe write end, select() marks
         * pipe_rd readable; read() then returns EOF.  nativeStop() also
         * closes g_listen_sock, making select() return on srv too. */
        g_listen_sock = srv;
        while (fd == INVALID_SOCK) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(srv, &rfds);
            FD_SET(pipe_rd, &rfds);
            int maxfd = (srv > pipe_rd ? srv : pipe_rd) + 1;

            struct timeval tv = { .tv_sec = 0, .tv_usec = 250000 }; /* 250ms */
            int ready = select(maxfd, &rfds, NULL, NULL, &tv);
            if (ready < 0) break;

            if (FD_ISSET(pipe_rd, &rfds)) {
                /* nativeStop() closed pipe (or CMD_QUIT fallback) — abort */
                LOGI("quit received during listen");
                close_sock(srv);
                g_listen_sock = INVALID_SOCK;
                jni_call_str(env, cb, mid_onDisconnected, "Session ended by user", "quit_listen");
                goto cleanup;
            }

            if (FD_ISSET(srv, &rfds)) {
                fd = accept(srv, NULL, NULL);
            }
        }
        close_sock(srv);
        g_listen_sock = INVALID_SOCK;
        we_init = 0;
    }

    free(host);
    host = NULL;
    free(socks5_host);
    socks5_host = NULL;
    free(socks5_port);
    socks5_port = NULL;

    if (fd == INVALID_SOCK) {
        LOGE("connection failed");
        jni_call_str(env, cb, mid_onConnectionFailed, "Connection failed", "conn_fail");
        goto cleanup;
    }

    LOGI("connected (we_init=%d)", we_init);
    g_session_sock = fd;  /* publish so nativeStop() can shutdown() */
    (*env)->CallVoidMethod(env, cb, mid_onConnected);
    jni_callback_ok(env);

    /* ================================================================
     * Phase 2: Handshake
     * ================================================================ */

    {
        uint8_t commit_self[KEY], commit_peer[KEY];
        uint8_t sas_key[KEY];
        char    sas[20];

        if (has_prekey) {
            memcpy(self_priv, prekey_priv, KEY);
            memcpy(self_pub,  prekey_pub,  KEY);
            crypto_wipe(prekey_priv, KEY);
            crypto_wipe(prekey_pub,  KEY);
            has_prekey = 0;
        } else {
            gen_keypair(self_priv, self_pub);
        }
        make_commit(commit_self, self_pub);

        set_sock_timeout(fd, HANDSHAKE_TIMEOUT_S);

        /* Version exchange */
        {
            uint8_t my_ver   = (uint8_t)PROTOCOL_VERSION;
            uint8_t peer_ver = 0;
            if (exchange(fd, we_init, &my_ver, 1, &peer_ver, 1) != 0) {
                LOGE("handshake error (version exchange)");
                crypto_wipe(commit_self, sizeof commit_self);
                jni_call_str(env, cb, mid_onHandshakeFailed, "Version exchange failed", "ver_xchg");
                goto cleanup_keys;
            }
            if (peer_ver != PROTOCOL_VERSION) {
                LOGE("version mismatch: we=%d peer=%d", PROTOCOL_VERSION, (int)peer_ver);
                crypto_wipe(commit_self, sizeof commit_self);
                jni_call_str(env, cb, mid_onHandshakeFailed, "Protocol version mismatch", "ver_mismatch");
                goto cleanup_keys;
            }
        }

        /* Commitment exchange */
        if (exchange(fd, we_init, commit_self, KEY, commit_peer, KEY) != 0) {
            LOGE("handshake error (commitments)");
            crypto_wipe(commit_self, sizeof commit_self);
            crypto_wipe(commit_peer, sizeof commit_peer);
            jni_call_str(env, cb, mid_onHandshakeFailed, "Commitment exchange failed", "commit_xchg");
            goto cleanup_keys;
        }

        /* Key reveal */
        if (exchange(fd, we_init, self_pub, KEY, peer_pub, KEY) != 0) {
            LOGE("handshake error (keys)");
            crypto_wipe(commit_self, sizeof commit_self);
            crypto_wipe(commit_peer, sizeof commit_peer);
            jni_call_str(env, cb, mid_onHandshakeFailed, "Key exchange failed", "key_xchg");
            goto cleanup_keys;
        }

        set_sock_timeout(fd, 0);

        /* Verify commitment */
        if (!verify_commit(commit_peer, peer_pub)) {
            LOGE("commitment mismatch -- possible MITM");
            crypto_wipe(commit_self, sizeof commit_self);
            crypto_wipe(commit_peer, sizeof commit_peer);
            jni_call_str(env, cb, mid_onHandshakeFailed, "Commitment mismatch (possible MITM)", "commit_verify");
            goto cleanup_keys;
        }

        crypto_wipe(commit_self, sizeof commit_self);
        crypto_wipe(commit_peer, sizeof commit_peer);

        /* Compute and verify peer fingerprint */
        {
            uint8_t peer_hash[32];
            domain_hash(peer_hash, "cipher fingerprint v2", peer_pub, KEY);

            char peer_fp_str[20];
            snprintf(peer_fp_str, 20, "%02X%02X-%02X%02X-%02X%02X-%02X%02X",
                     peer_hash[0], peer_hash[1], peer_hash[2], peer_hash[3],
                     peer_hash[4], peer_hash[5], peer_hash[6], peer_hash[7]);

            int fp_matched = 0;
            if (has_peer_fp) {
                if (ct_compare(peer_hash, expected_peer_fp, 8) != 0) {
                    LOGE("peer fingerprint mismatch");
                    crypto_wipe(peer_hash, sizeof peer_hash);
                    crypto_wipe(expected_peer_fp, sizeof expected_peer_fp);
                    jni_call_str(env, cb, mid_onHandshakeFailed, "Peer fingerprint mismatch", "fp_mismatch");
                    goto cleanup_keys;
                }
                fp_matched = 1;
                crypto_wipe(expected_peer_fp, sizeof expected_peer_fp);
            }

            jstring fp_jstr = (*env)->NewStringUTF(env, peer_fp_str);
            if (!fp_jstr) { LOGE("NewStringUTF(fp) failed"); crypto_wipe(peer_hash, sizeof peer_hash); crypto_wipe(peer_fp_str, sizeof peer_fp_str); goto cleanup_keys; }
            jboolean verified = fp_matched ? JNI_TRUE : JNI_FALSE;
            (*env)->CallVoidMethod(env, cb, mid_onPeerFingerprintReady, fp_jstr, verified);
            (*env)->DeleteLocalRef(env, fp_jstr);
            jni_callback_ok(env);
            crypto_wipe(peer_hash, sizeof peer_hash);
            crypto_wipe(peer_fp_str, sizeof peer_fp_str);
        }

        /* Derive session keys */
        if (session_init(&sess, we_init, self_priv, self_pub, peer_pub,
                         sas_key) != 0) {
            LOGE("key agreement failed (bad peer key)");
            crypto_wipe(sas_key, sizeof sas_key);
            jni_call_str(env, cb, mid_onHandshakeFailed, "Key agreement failed", "key_agree");
            goto cleanup_keys;
        }

        /* Wipe the private key immediately — no longer needed. */
        crypto_wipe(self_priv, sizeof self_priv);

        format_sas(sas, sas_key);
        crypto_wipe(sas_key, sizeof sas_key);

        LOGI("handshake complete, SAS ready");

        /* Callback: SAS ready for user verification */
        jstring sas_jstr = (*env)->NewStringUTF(env, sas);
        crypto_wipe(sas, sizeof sas);
        if (!sas_jstr) { LOGE("NewStringUTF(sas) failed"); goto cleanup_session; }
        (*env)->CallVoidMethod(env, cb, mid_onSasReady, sas_jstr);
        (*env)->DeleteLocalRef(env, sas_jstr);
        if (jni_callback_ok(env) != 0) goto cleanup_session;
    }

    /* ================================================================
     * Phase 3: Wait for SAS confirmation from Java (via pipe)
     *
     * Blocking read on pipe.  If nativeStop() closes the write end,
     * read() returns 0 (EOF) and pipe_read_exact() returns -1, which
     * we catch here.  CMD_QUIT is still handled below as a fallback.
     * ================================================================ */

    {
        uint8_t hdr[3];
        if (pipe_read_exact(pipe_rd, hdr, 3) != 0) {
            LOGE("pipe read failed waiting for SAS confirm");
            jni_call_str(env, cb, mid_onDisconnected, "Internal error", "sas_pipe");
            goto cleanup_session;
        }

        uint8_t cmd = hdr[0];
        if (cmd == CMD_QUIT) {
            LOGI("quit received during SAS wait");
            jni_call_str(env, cb, mid_onDisconnected, "Session ended by user", "quit_sas");
            goto cleanup_session;
        }
        if (cmd != CMD_CONFIRM_SAS) {
            LOGE("unexpected command 0x%02x during SAS wait", cmd);
            jni_call_str(env, cb, mid_onDisconnected, "Unexpected command", "sas_bad_cmd");
            goto cleanup_session;
        }

        /* Skip any payload (CMD_CONFIRM_SAS has none, but be safe) */
        uint16_t plen = (uint16_t)(hdr[1] | (hdr[2] << 8));
        if (plen > 0) {
            uint8_t discard[512];
            while (plen > 0) {
                size_t chunk = plen < sizeof discard ? plen : sizeof discard;
                if (pipe_read_exact(pipe_rd, discard, chunk) != 0) break;
                plen -= (uint16_t)chunk;
            }
        }

        LOGI("SAS confirmed, entering chat loop");
    }

    /* ================================================================
     * Phase 4: Event loop — poll on socket + pipe
     * ================================================================ */

    /* Set frame timeout so a stalled partial frame doesn't hang forever.
     * Unlike the handshake timeout, this only fires if a frame *starts*
     * arriving but never completes.  Idle sessions are fine. */
    set_sock_timeout(fd, FRAME_TIMEOUT_S);

    {
        struct pollfd fds[2];
        fds[0].fd     = (int)fd;
        fds[0].events = POLLIN;
        fds[1].fd     = pipe_rd;
        fds[1].events = POLLIN;

        int running = 1;
        while (running) {
            int ret = poll(fds, 2, -1);  /* block until activity */
            if (ret < 0) {
                if (errno == EINTR) continue;
                LOGE("poll error: %s", strerror(errno));
                break;
            }

            /* --- Socket readable: incoming encrypted frame --- */
            if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
                uint8_t  frame[FRAME_SZ];
                uint8_t  plain[MAX_MSG + 1];
                uint16_t plen = 0;

                if (read_exact(fd, frame, FRAME_SZ) != 0) {
                    LOGI("peer disconnected (read_exact failed)");
                    crypto_wipe(frame, sizeof frame);
                    jni_call_str(env, cb, mid_onDisconnected, "Peer disconnected", "peer_dc");
                    break;
                }

                if (frame_open(&sess, frame, plain, &plen) != 0) {
                    LOGE("frame_open failed (auth or sequence error)");
                    crypto_wipe(frame, sizeof frame);
                    crypto_wipe(plain, sizeof plain);
                    jni_call_str(env, cb, mid_onDisconnected, "Decryption failed", "decrypt_fail");
                    break;
                }

                plain[plen] = '\0';
                sanitize_peer_text(plain, plen);

                jstring text = (*env)->NewStringUTF(env, (char *)plain);
                if (!text) {
                    LOGE("NewStringUTF(message) failed");
                    crypto_wipe(frame, sizeof frame);
                    crypto_wipe(plain, sizeof plain);
                    break;
                }
                (*env)->CallVoidMethod(env, cb, mid_onMessageReceived, text);
                (*env)->DeleteLocalRef(env, text);
                if (jni_callback_ok(env) != 0) {
                    crypto_wipe(frame, sizeof frame);
                    crypto_wipe(plain, sizeof plain);
                    break;
                }

                crypto_wipe(frame, sizeof frame);
                crypto_wipe(plain, sizeof plain);
            }

            /* --- Pipe readable: command from Java, or nativeStop() ---
             * POLLHUP/POLLERR: nativeStop() closed the write end;
             * pipe_read_exact() returns EOF and we break out.
             * POLLIN: normal command (CMD_SEND, CMD_CONFIRM_SAS,
             * or CMD_QUIT fallback). */
            if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
                uint8_t hdr[3];
                if (pipe_read_exact(pipe_rd, hdr, 3) != 0) {
                    /* EOF from nativeStop() pipe close, or read error */
                    break;
                }

                uint8_t  cmd  = hdr[0];
                uint16_t plen = (uint16_t)(hdr[1] | (hdr[2] << 8));

                if (cmd == CMD_QUIT) {
                    LOGI("CMD_QUIT received");
                    /* Drain any payload (CMD_QUIT shouldn't have one) */
                    if (plen > 0) {
                        uint8_t discard[512];
                        while (plen > 0) {
                            size_t chunk = plen < sizeof discard ? plen : sizeof discard;
                            if (pipe_read_exact(pipe_rd, discard, chunk) != 0) break;
                            plen -= (uint16_t)chunk;
                        }
                    }
                    jni_call_str(env, cb, mid_onDisconnected, "Session ended", "quit_cmd");
                    running = 0;

                } else if (cmd == CMD_SEND) {
                    /* Read the message payload */
                    uint8_t msg_buf[MAX_MSG + 1];
                    if (plen > MAX_MSG) {
                        LOGE("CMD_SEND payload too large: %d", (int)plen);
                        /* Drain oversized payload */
                        uint8_t discard[512];
                        uint16_t remaining = plen;
                        while (remaining > 0) {
                            size_t chunk = remaining < sizeof discard ? remaining : sizeof discard;
                            if (pipe_read_exact(pipe_rd, discard, chunk) != 0) break;
                            remaining -= (uint16_t)chunk;
                        }
                        (*env)->CallVoidMethod(env, cb, mid_onSendResult, (jboolean)0);
                        jni_callback_ok(env);
                        continue;
                    }

                    if (plen > 0 && pipe_read_exact(pipe_rd, msg_buf, plen) != 0) {
                        LOGE("pipe read error on CMD_SEND payload");
                        break;
                    }

                    /* Encrypt and send */
                    uint8_t frame[FRAME_SZ], next_tx[KEY];
                    if (frame_build(&sess,
                                    msg_buf, plen,
                                    frame, next_tx) != 0) {
                        LOGE("frame_build failed");
                        crypto_wipe(frame, sizeof frame);
                        crypto_wipe(next_tx, sizeof next_tx);
                        crypto_wipe(msg_buf, plen);
                        (*env)->CallVoidMethod(env, cb, mid_onSendResult, (jboolean)0);
                        jni_callback_ok(env);
                        continue;
                    }

                    if (write_exact(fd, frame, FRAME_SZ) != 0) {
                        LOGE("write_exact failed");
                        crypto_wipe(frame, sizeof frame);
                        crypto_wipe(next_tx, sizeof next_tx);
                        crypto_wipe(msg_buf, plen);
                        (*env)->CallVoidMethod(env, cb, mid_onSendResult, (jboolean)0);
                        jni_callback_ok(env);
                        jni_call_str(env, cb, mid_onDisconnected, "Send failed (connection lost)", "send_fail");
                        running = 0;
                        continue;
                    }

                    /* Commit chain advance after successful send */
                    memcpy(sess.tx, next_tx, KEY);
                    sess.tx_seq++;

                    crypto_wipe(frame, sizeof frame);
                    crypto_wipe(next_tx, sizeof next_tx);
                    crypto_wipe(msg_buf, plen);

                    (*env)->CallVoidMethod(env, cb, mid_onSendResult, (jboolean)1);
                    jni_callback_ok(env);

                } else {
                    LOGE("unknown command 0x%02x, draining %d bytes", cmd, (int)plen);
                    uint8_t discard[512];
                    while (plen > 0) {
                        size_t chunk = plen < sizeof discard ? plen : sizeof discard;
                        if (pipe_read_exact(pipe_rd, discard, chunk) != 0) break;
                        plen -= (uint16_t)chunk;
                    }
                }
            }
        }
    }

    goto cleanup_session;

    /* ================================================================
     * Cleanup paths
     * ================================================================ */

cleanup_keys:
    /* Handshake failed — wipe key material */
    crypto_wipe(self_priv, sizeof self_priv);
    crypto_wipe(self_pub,  sizeof self_pub);
    crypto_wipe(peer_pub,  sizeof peer_pub);
    crypto_wipe(expected_peer_fp, sizeof expected_peer_fp);
    goto cleanup;

cleanup_session:
    /* Normal exit or post-handshake error — wipe session + keys */
    session_wipe(&sess);
    crypto_wipe(self_pub,  sizeof self_pub);
    crypto_wipe(peer_pub,  sizeof peer_pub);

cleanup:
    /* Wipe pre-generated key material if still on the stack */
    crypto_wipe(prekey_priv, sizeof prekey_priv);
    crypto_wipe(prekey_pub,  sizeof prekey_pub);
    /* Close socket — clear the global first so nativeStop() won't
     * try to shutdown() a closed fd. */
    g_session_sock = INVALID_SOCK;
    if (fd != INVALID_SOCK) {
        sock_shutdown_both(fd);
        close_sock(fd);
    }

    /* Close our read end of the pipe.  The write end (g_pipe_wr) is
     * owned exclusively by the Java-side globals — the thread never
     * touches it.  This single-owner design prevents stale-fd and
     * double-close bugs: only nativeStart() opens and closes g_pipe_wr. */
    close(pipe_rd);

    /* Delete the JNI global ref to the callback */
    (*env)->DeleteGlobalRef(env, cb);

    /* Detach from JVM */
    (*g_jvm)->DetachCurrentThread(g_jvm);

    /* Only clear g_session_active if our generation still matches.
     * If nativeStart() already spawned a newer session (incremented
     * g_session_gen), we must not clobber the newer session's active bit. */
    if (g_session_gen == my_gen)
        g_session_active = 0;
    LOGI("session thread exiting (gen=%d)", my_gen);
    return NULL;
}

/* ---- JNI exports -------------------------------------------------------- */

/*
 * JNI_OnLoad — called once when System.loadLibrary("simplecipher") runs.
 * We cache the JavaVM pointer so the native thread can attach later.
 */
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_jvm = vm;

    /* Block ptrace and /proc/self/mem access — prevents memory dumping
     * of crypto keys by a compromised app or debugger. */
    prctl(PR_SET_DUMPABLE, 0);

    /* Disable core dumps — a crash must never write key material to disk.
     * Set soft limit first (always allowed), then try hard limit. */
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_CORE, &rl) == 0) {
            rl.rlim_cur = 0;
            setrlimit(RLIMIT_CORE, &rl);
            rl.rlim_max = 0;
            (void)setrlimit(RLIMIT_CORE, &rl);
        }
    }

    return JNI_VERSION_1_6;
}

/*
 * nativeStart — create pipe, resolve method IDs, spawn session thread.
 *
 * mode: 0 = listen, 1 = connect
 * Returns 0 on success, -1 on failure.
 */
JNIEXPORT jint JNICALL
Java_com_example_simplecipher_ChatActivity_nativeStart(
        JNIEnv *env, jobject thiz, jint mode, jstring host, jint port,
        jstring socks5_proxy, jobject callback) {

    plat_init();

    /* Close any stale pipe write fd — even if g_session_active is already 0.
     * Without this, a finished session leaves g_pipe_wr open (fd leak). */
    {
        int wr = g_pipe_wr;
        g_pipe_wr = -1;
        if (wr >= 0) close(wr);
    }

    /* Wait for any previous session thread to finish.  This ensures the
     * old socket is fully closed before we try to bind the same port.
     * Without this, listen→back→listen fails with "address in use". */
    if (g_session_active) {
        /* Shutdown session socket to unblock read_exact/write_exact */
        {
            socket_t s = g_session_sock;
            if (s != INVALID_SOCK) sock_shutdown_both(s);
        }
        /* Close the listen socket to unblock accept() if still waiting */
        socket_t ls = g_listen_sock;
        if (ls != INVALID_SOCK) {
            g_listen_sock = INVALID_SOCK;
            close_sock(ls);
        }
        /* Wait for thread to exit.  Poll g_session_active with short
         * sleeps rather than pthread_timedjoin_np (not available on Bionic). */
        for (int i = 0; i < 20 && g_session_active; i++) {
            usleep(100000);  /* 100ms × 20 = 2s max wait */
        }
        if (g_session_active) {
            LOGE("previous session thread did not exit in time");
        } else {
            pthread_join(g_session_thread, NULL);
        }
        g_session_active = 0;
    }

    /* Create the command pipe.  The write end is set non-blocking so that
     * nativePostCommand() (called on the Java/UI thread) never blocks.
     * If the pipe is full (session thread stuck in a socket write), the
     * command is dropped — acceptable because a stuck thread will time out
     * via SO_SNDTIMEO and drain the pipe, or the next nativeStart() will
     * tear it down.  Without O_NONBLOCK, a malicious peer that stops
     * reading can indirectly block the Android UI thread. */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        LOGE("pipe() failed: %s", strerror(errno));
        return -1;
    }
    {
        int flags = fcntl(pipefd[1], F_GETFL);
        if (flags != -1) fcntl(pipefd[1], F_SETFL, flags | O_NONBLOCK);
    }

    /* Store the write end globally for nativePostCommand */
    g_pipe_wr = pipefd[1];

    /* Resolve method IDs on the caller's thread (class loaders are
     * per-thread on Android; the native thread may not find the class). */
    jclass cls = (*env)->GetObjectClass(env, callback);
    if (!cls) {
        LOGE("GetObjectClass failed for callback");
        close(pipefd[0]);
        close(pipefd[1]);
        g_pipe_wr = -1;
        return -1;
    }

    /* Build the thread argument struct */
    thread_arg_t *ta = calloc(1, sizeof(thread_arg_t));
    if (!ta) {
        LOGE("calloc failed");
        close(pipefd[0]);
        close(pipefd[1]);
        g_pipe_wr = -1;
        return -1;
    }

    ta->mode    = (int)mode;
    ta->port    = (int)port;
    ta->pipe_rd = pipefd[0];
    ta->gen     = ++g_session_gen;  /* unique generation for this session */

    /* Copy host string (connect mode only).
     * GetStringUTFChars may return NULL on OOM (JNI spec).  If so,
     * strdup(NULL) is undefined — guard against it. */
    if (host) {
        const char *h = (*env)->GetStringUTFChars(env, host, NULL);
        if (!h) {
            LOGE("GetStringUTFChars failed (OOM)");
            free(ta);
            close(pipefd[0]);
            close(pipefd[1]);
            g_pipe_wr = -1;
            return -1;
        }
        ta->host = strdup(h);
        (*env)->ReleaseStringUTFChars(env, host, h);
        if (!ta->host) {
            LOGE("strdup(host) failed (OOM)");
            free(ta);
            close(pipefd[0]);
            close(pipefd[1]);
            g_pipe_wr = -1;
            return -1;
        }
    } else {
        ta->host = NULL;
    }

    /* Parse SOCKS5 proxy string "host:port" (e.g. "127.0.0.1:9050").
     * If null or empty, direct connect is used.
     *
     * SECURITY: if the user provided a non-empty proxy string but it
     * fails to parse, we MUST abort — not silently fall through to
     * direct connect, which would leak the user's IP address. */
    ta->socks5_host = NULL;
    ta->socks5_port = NULL;
    if (socks5_proxy) {
        const char *p = (*env)->GetStringUTFChars(env, socks5_proxy, NULL);
        if (!p) {
            /* OOM on a non-null proxy string — fail closed. */
            LOGE("GetStringUTFChars(socks5_proxy) failed (OOM)");
            free(ta->host);
            free(ta);
            close(pipefd[0]);
            close(pipefd[1]);
            g_pipe_wr = -1;
            return -1;
        }
        if (p[0]) {
            const char *colon = strrchr(p, ':');
            if (colon && colon != p && colon[1]) {
                size_t hlen = (size_t)(colon - p);
                ta->socks5_host = strndup(p, hlen);
                ta->socks5_port = strdup(colon + 1);
                /* Defence in depth: reject non-loopback proxies.
                 * Blocking connect to a remote proxy can hang the
                 * session thread beyond nativeStop()'s reach. */
                if (ta->socks5_host &&
                    strcmp(ta->socks5_host, "127.0.0.1") != 0 &&
                    strcmp(ta->socks5_host, "localhost") != 0 &&
                    strcmp(ta->socks5_host, "::1") != 0) {
                    LOGE("SOCKS5 proxy must be localhost, got: %s", ta->socks5_host);
                    free(ta->socks5_host);
                    free(ta->socks5_port);
                    (*env)->ReleaseStringUTFChars(env, socks5_proxy, p);
                    free(ta->host);
                    free(ta);
                    close(pipefd[0]);
                    close(pipefd[1]);
                    g_pipe_wr = -1;
                    return -1;
                }
                if (!ta->socks5_host || !ta->socks5_port) {
                    /* OOM on strdup — fail closed, don't fall to direct connect */
                    LOGE("SOCKS5 strdup failed (OOM)");
                    free(ta->socks5_host);
                    free(ta->socks5_port);
                    (*env)->ReleaseStringUTFChars(env, socks5_proxy, p);
                    free(ta->host);
                    free(ta);
                    close(pipefd[0]);
                    close(pipefd[1]);
                    g_pipe_wr = -1;
                    return -1;
                }
            } else {
                /* Non-empty proxy string but bad format — fail closed. */
                LOGE("SOCKS5 proxy string malformed (expected host:port): %s", p);
                (*env)->ReleaseStringUTFChars(env, socks5_proxy, p);
                free(ta->host);
                free(ta);
                close(pipefd[0]);
                close(pipefd[1]);
                g_pipe_wr = -1;
                return -1;
            }
        }
        (*env)->ReleaseStringUTFChars(env, socks5_proxy, p);
    }

    /* Copy pre-generated key into thread arg, then wipe globals */
    if (g_prekey_valid) {
        memcpy(ta->prekey_priv, g_prekey_priv, KEY);
        memcpy(ta->prekey_pub,  g_prekey_pub,  KEY);
        ta->has_prekey = 1;
        crypto_wipe(g_prekey_priv, KEY);
        crypto_wipe(g_prekey_pub,  KEY);
        g_prekey_valid = 0;
    } else {
        ta->has_prekey = 0;
    }

    if (g_peer_fp_valid) {
        memcpy(ta->peer_fp, g_peer_fp, 8);
        ta->has_peer_fp = 1;
        crypto_wipe(g_peer_fp, 8);
        g_peer_fp_valid = 0;
    } else {
        ta->has_peer_fp = 0;
    }

    /* Create a JNI global ref so the callback survives across threads */
    ta->callback = (*env)->NewGlobalRef(env, callback);
    if (!ta->callback) {
        LOGE("NewGlobalRef failed (OOM)");
        free(ta->socks5_host);
        free(ta->socks5_port);
        free(ta->host);
        free(ta);
        close(pipefd[0]);
        close(pipefd[1]);
        g_pipe_wr = -1;
        return -1;
    }

    /* Look up all 7 callback method IDs */
    ta->mid_onConnected        = (*env)->GetMethodID(env, cls, "onConnected",        "()V");
    ta->mid_onConnectionFailed = (*env)->GetMethodID(env, cls, "onConnectionFailed", "(Ljava/lang/String;)V");
    ta->mid_onSasReady         = (*env)->GetMethodID(env, cls, "onSasReady",         "(Ljava/lang/String;)V");
    ta->mid_onHandshakeFailed  = (*env)->GetMethodID(env, cls, "onHandshakeFailed",  "(Ljava/lang/String;)V");
    ta->mid_onMessageReceived  = (*env)->GetMethodID(env, cls, "onMessageReceived",  "(Ljava/lang/String;)V");
    ta->mid_onSendResult       = (*env)->GetMethodID(env, cls, "onSendResult",       "(Z)V");
    ta->mid_onDisconnected     = (*env)->GetMethodID(env, cls, "onDisconnected",     "(Ljava/lang/String;)V");
    ta->mid_onPeerFingerprintReady = (*env)->GetMethodID(env, cls, "onPeerFingerprintReady",
                                                          "(Ljava/lang/String;Z)V");

    /* Verify all method IDs resolved */
    if (!ta->mid_onConnected || !ta->mid_onConnectionFailed ||
        !ta->mid_onSasReady || !ta->mid_onHandshakeFailed ||
        !ta->mid_onMessageReceived || !ta->mid_onSendResult ||
        !ta->mid_onDisconnected || !ta->mid_onPeerFingerprintReady) {
        LOGE("failed to resolve one or more callback method IDs");
        (*env)->DeleteGlobalRef(env, ta->callback);
        free(ta->host);
        free(ta);
        close(pipefd[0]);
        close(pipefd[1]);
        g_pipe_wr = -1;
        return -1;
    }

    /* Mark session active BEFORE spawning the thread.  If the thread
     * fails and exits before we resume, its cleanup clears the flag
     * via the generation guard.  Publishing after pthread_create()
     * would race: a fast-exiting thread could clear 0 before the
     * parent stores 1, leaving a stale "active" flag. */
    g_session_active = 1;

    /* Create joinable (not detached) so nativeStart can wait for the
     * previous thread to finish before binding the same port again. */
    int rc = pthread_create(&g_session_thread, NULL, session_thread, ta);

    if (rc != 0) {
        LOGE("pthread_create failed: %d", rc);
        g_session_active = 0;
        (*env)->DeleteGlobalRef(env, ta->callback);
        free(ta->host);
        free(ta);
        close(pipefd[0]);
        close(pipefd[1]);
        g_pipe_wr = -1;
        return -1;
    }
    LOGI("session thread spawned (mode=%d, port=%d)", (int)mode, (int)port);
    return 0;
}

/*
 * nativePostCommand — write a command to the native thread's pipe.
 *
 * Format: [cmd_byte][len_le16][payload]
 * Total size is always < PIPE_BUF so the write is atomic.
 *
 * Returns JNI_TRUE if the write succeeded, JNI_FALSE if the pipe was
 * full (EAGAIN) or any other error occurred.  The Java side uses this
 * to avoid showing phantom "sent" messages under backpressure.
 */
JNIEXPORT jboolean JNICALL
Java_com_example_simplecipher_ChatActivity_nativePostCommand(
        JNIEnv *env, jobject thiz, jint cmd, jbyteArray payload) {

    int wr = g_pipe_wr;
    if (wr < 0) {
        /* No active session. */
        return JNI_FALSE;
    }

    /* Determine payload length */
    uint16_t plen = 0;
    jbyte *pbuf = NULL;
    if (payload) {
        jsize jlen = (*env)->GetArrayLength(env, payload);
        if (jlen > MAX_MSG) {
            LOGE("nativePostCommand: payload too large (%d > %d)", (int)jlen, MAX_MSG);
            return JNI_FALSE;
        }
        plen = (uint16_t)jlen;
        pbuf = (*env)->GetByteArrayElements(env, payload, NULL);
        if (!pbuf) {
            /* JNI allocation failure (OOM).  Do NOT proceed with plen > 0
             * and a NULL buffer — that would write uninitialized bytes. */
            LOGE("GetByteArrayElements failed (OOM)");
            return JNI_FALSE;
        }
    }

    /* Build the command buffer: [cmd(1)][len_le16(2)][payload(plen)]
     * Max total = 1 + 2 + 486 = 489, well under PIPE_BUF (4096). */
    uint8_t buf[3 + MAX_MSG];
    buf[0] = (uint8_t)cmd;
    buf[1] = (uint8_t)(plen & 0xFF);
    buf[2] = (uint8_t)((plen >> 8) & 0xFF);
    if (plen > 0) {
        memcpy(buf + 3, pbuf, plen);
    }

    jboolean ok = JNI_TRUE;
    ssize_t written = write(wr, buf, 3 + plen);
    if (written < 0) {
        ok = JNI_FALSE;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            LOGE("pipe full — command dropped (session thread may be blocked)");
        } else {
            LOGE("pipe write failed: %s", strerror(errno));
        }
    }

    (*env)->ReleaseByteArrayElements(env, payload, pbuf, JNI_ABORT);
    return ok;
}

/*
 * nativeStop — forced, non-droppable session teardown.
 *
 * Unlike CMD_QUIT (which goes through the pipe and can be dropped if the
 * pipe is full), this function acts out-of-band by directly closing and
 * shutting down the resources the session thread is blocked on:
 *
 *   1. Close the pipe write end → POLLHUP on the read end (connect-phase
 *      poll) or EOF from pipe_read_exact() (session-phase reads)
 *   2. Shutdown the session socket → read_exact()/write_exact() return -1
 *   3. Close the listen socket → select()/accept() return -1
 *
 * The session thread detects these errors, breaks out of whatever phase
 * it is in, and exits via cleanup.  This guarantees the thread unblocks
 * promptly regardless of peer behavior or network conditions.
 *
 * Called from ChatActivity.onStop(), onBackPressed(), and onDestroy().
 */
JNIEXPORT void JNICALL
Java_com_example_simplecipher_ChatActivity_nativeStop(
        JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;

    /* 1. Close pipe write end → POLLHUP on read end (connect/chat poll)
     *    or EOF from pipe_read_exact (SAS wait, event loop reads) */
    {
        int wr = g_pipe_wr;
        g_pipe_wr = -1;
        if (wr >= 0) close(wr);
    }

    /* 2. Shutdown session socket → unblock read_exact/write_exact */
    {
        socket_t s = g_session_sock;
        if (s != INVALID_SOCK) {
            /* shutdown() signals the thread without closing the fd.
             * The thread still owns the fd for close() in cleanup. */
            sock_shutdown_both(s);
        }
    }

    /* 3. Close listen socket → unblock select/accept */
    {
        socket_t ls = g_listen_sock;
        g_listen_sock = INVALID_SOCK;
        if (ls != INVALID_SOCK) close_sock(ls);
    }
}

JNIEXPORT jstring JNICALL
Java_com_example_simplecipher_MainActivity_nativeGenerateKey(
        JNIEnv *env, jobject thiz) {
    (void)thiz;
    if (g_prekey_valid) {
        crypto_wipe(g_prekey_priv, KEY);
        crypto_wipe(g_prekey_pub,  KEY);
        g_prekey_valid = 0;
    }
    gen_keypair(g_prekey_priv, g_prekey_pub);
    g_prekey_valid = 1;
    char fp[20];
    format_fingerprint(fp, g_prekey_pub);
    jstring result = (*env)->NewStringUTF(env, fp);
    crypto_wipe(fp, sizeof fp);
    return result;
}

JNIEXPORT void JNICALL
Java_com_example_simplecipher_MainActivity_nativeWipePreKey(
        JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    if (g_prekey_valid) {
        crypto_wipe(g_prekey_priv, KEY);
        crypto_wipe(g_prekey_pub,  KEY);
        g_prekey_valid = 0;
    }
    if (g_peer_fp_valid) {
        crypto_wipe(g_peer_fp, 8);
        g_peer_fp_valid = 0;
    }
}

JNIEXPORT void JNICALL
Java_com_example_simplecipher_MainActivity_nativeSetPeerFingerprint(
        JNIEnv *env, jobject thiz, jstring fingerprint) {
    (void)thiz;
    const char *fp_str = (*env)->GetStringUTFChars(env, fingerprint, NULL);
    if (!fp_str) {
        /* OOM — clear any stale fingerprint rather than leaving it armed */
        crypto_wipe(g_peer_fp, sizeof g_peer_fp);
        g_peer_fp_valid = 0;
        return;
    }
    if (parse_fingerprint(g_peer_fp, fp_str) == 0) {
        g_peer_fp_valid = 1;
    } else {
        LOGE("nativeSetPeerFingerprint: malformed fingerprint string");
        g_peer_fp_valid = 0;
    }
    (*env)->ReleaseStringUTFChars(env, fingerprint, fp_str);
}

JNIEXPORT void JNICALL
Java_com_example_simplecipher_MainActivity_nativeClearPeerFingerprint(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    crypto_wipe(g_peer_fp, sizeof g_peer_fp);
    g_peer_fp_valid = 0;
}
