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
 *   A single thread with exclusive ownership of all mutable state makes
 *   data races structurally impossible — no mutex needed.
 *
 * Command protocol (pipe):
 *   [1 byte: cmd] [2 bytes: payload length, little-endian] [payload]
 *   All writes are < PIPE_BUF (4096) so they are atomic from any thread.
 *
 * CMD_SEND         = 0x01  (payload = UTF-8 message, max 486 bytes)
 * CMD_CONFIRM_SAS  = 0x02  (no payload)
 * CMD_QUIT         = 0x03  (no payload)
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
#include <poll.h>
#include <sys/prctl.h>
#include <sys/resource.h>

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

/* Write end of the command pipe.  This is the ONLY mutable global that
 * Java touches (via nativePostCommand).  Writes are atomic because the
 * command header + payload is always < PIPE_BUF (4096 bytes). */
static int g_pipe_wr = -1;

/* Listen socket — set while the native thread is blocked in accept().
 * nativePostCommand(CMD_QUIT) closes this to unblock accept() so the
 * thread can exit promptly when the user presses Back. */
static volatile socket_t g_listen_sock = INVALID_SOCK;

/* Session thread handle — used to join the thread before starting a new
 * session, ensuring the previous socket is fully closed. */
static pthread_t g_session_thread;
static volatile int g_session_active = 0;

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
    int       mode;       /* 0 = listen, 1 = connect                    */
    char     *host;       /* strdup'd host string (connect only), or NULL */
    int       port;
    int       pipe_rd;    /* read end of command pipe                    */
    jobject   callback;   /* JNI global ref to NativeCallback            */

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

static int ct_compare(const uint8_t *a, const uint8_t *b, size_t n) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff;
}

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

static void *session_thread(void *arg) {
    thread_arg_t *ta = (thread_arg_t *)arg;

    /* Copy everything we need from the arg struct, then free it.
     * This avoids a dangling pointer if the caller's stack unwinds. */
    int       mode    = ta->mode;
    char     *host    = ta->host;       /* we own this (strdup'd) */
    int       port    = ta->port;
    int       pipe_rd = ta->pipe_rd;
    jobject   cb      = ta->callback;   /* global ref — we delete on exit */

    jmethodID mid_onConnected        = ta->mid_onConnected;
    jmethodID mid_onConnectionFailed = ta->mid_onConnectionFailed;
    jmethodID mid_onSasReady         = ta->mid_onSasReady;
    jmethodID mid_onHandshakeFailed  = ta->mid_onHandshakeFailed;
    jmethodID mid_onMessageReceived  = ta->mid_onMessageReceived;
    jmethodID mid_onSendResult       = ta->mid_onSendResult;
    jmethodID mid_onDisconnected     = ta->mid_onDisconnected;
    jmethodID mid_onPeerFingerprintReady = ta->mid_onPeerFingerprintReady;

    int       has_prekey  = ta->has_prekey;
    uint8_t   prekey_priv[KEY], prekey_pub[KEY];
    if (has_prekey) {
        memcpy(prekey_priv, ta->prekey_priv, KEY);
        memcpy(prekey_pub,  ta->prekey_pub,  KEY);
        crypto_wipe(ta->prekey_priv, KEY);
        crypto_wipe(ta->prekey_pub,  KEY);
    }

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
        free(host);
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

    if (mode == 1) {
        /* Connect mode */
        LOGI("connecting to %s:%s", host ? host : "(null)", port_str);
        fd = connect_socket(host, port_str);
        we_init = 1;
    } else {
        /* Listen mode.
         *
         * We can't use listen_socket() directly because it blocks in
         * accept() with no way to interrupt it.  Instead, use select()
         * with a timeout so we can periodically check the pipe for
         * CMD_QUIT.  This lets the user press Back and immediately
         * re-listen on the same port. */
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
            jstring reason = (*env)->NewStringUTF(env, "Listen failed (getaddrinfo)");
            (*env)->CallVoidMethod(env, cb, mid_onConnectionFailed, reason);
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
            jstring reason = (*env)->NewStringUTF(env, "Listen failed (port in use?)");
            (*env)->CallVoidMethod(env, cb, mid_onConnectionFailed, reason);
            goto cleanup;
        }

        /* Poll: wait for either a peer connection or CMD_QUIT on the pipe. */
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
                /* CMD_QUIT arrived — abort listen */
                LOGI("quit received during listen");
                close_sock(srv);
                g_listen_sock = INVALID_SOCK;
                jstring reason = (*env)->NewStringUTF(env, "Session ended by user");
                (*env)->CallVoidMethod(env, cb, mid_onDisconnected, reason);
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

    if (fd == INVALID_SOCK) {
        LOGE("connection failed");
        jstring reason = (*env)->NewStringUTF(env, "Connection failed");
        (*env)->CallVoidMethod(env, cb, mid_onConnectionFailed, reason);
        goto cleanup;
    }

    LOGI("connected (we_init=%d)", we_init);
    (*env)->CallVoidMethod(env, cb, mid_onConnected);

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
                jstring reason = (*env)->NewStringUTF(env, "Version exchange failed");
                (*env)->CallVoidMethod(env, cb, mid_onHandshakeFailed, reason);
                goto cleanup_keys;
            }
            if (peer_ver != PROTOCOL_VERSION) {
                LOGE("version mismatch: we=%d peer=%d", PROTOCOL_VERSION, (int)peer_ver);
                crypto_wipe(commit_self, sizeof commit_self);
                jstring reason = (*env)->NewStringUTF(env, "Protocol version mismatch");
                (*env)->CallVoidMethod(env, cb, mid_onHandshakeFailed, reason);
                goto cleanup_keys;
            }
        }

        /* Commitment exchange */
        if (exchange(fd, we_init, commit_self, KEY, commit_peer, KEY) != 0) {
            LOGE("handshake error (commitments)");
            crypto_wipe(commit_self, sizeof commit_self);
            crypto_wipe(commit_peer, sizeof commit_peer);
            jstring reason = (*env)->NewStringUTF(env, "Commitment exchange failed");
            (*env)->CallVoidMethod(env, cb, mid_onHandshakeFailed, reason);
            goto cleanup_keys;
        }

        /* Key reveal */
        if (exchange(fd, we_init, self_pub, KEY, peer_pub, KEY) != 0) {
            LOGE("handshake error (keys)");
            crypto_wipe(commit_self, sizeof commit_self);
            crypto_wipe(commit_peer, sizeof commit_peer);
            jstring reason = (*env)->NewStringUTF(env, "Key exchange failed");
            (*env)->CallVoidMethod(env, cb, mid_onHandshakeFailed, reason);
            goto cleanup_keys;
        }

        set_sock_timeout(fd, 0);

        /* Verify commitment */
        if (!verify_commit(commit_peer, peer_pub)) {
            LOGE("commitment mismatch -- possible MITM");
            crypto_wipe(commit_self, sizeof commit_self);
            crypto_wipe(commit_peer, sizeof commit_peer);
            jstring reason = (*env)->NewStringUTF(env, "Commitment mismatch (possible MITM)");
            (*env)->CallVoidMethod(env, cb, mid_onHandshakeFailed, reason);
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
                    jstring reason = (*env)->NewStringUTF(env, "Peer fingerprint mismatch");
                    (*env)->CallVoidMethod(env, cb, mid_onHandshakeFailed, reason);
                    goto cleanup_keys;
                }
                fp_matched = 1;
                crypto_wipe(expected_peer_fp, sizeof expected_peer_fp);
            }

            jstring fp_jstr = (*env)->NewStringUTF(env, peer_fp_str);
            jboolean verified = fp_matched ? JNI_TRUE : JNI_FALSE;
            (*env)->CallVoidMethod(env, cb, mid_onPeerFingerprintReady, fp_jstr, verified);
            crypto_wipe(peer_hash, sizeof peer_hash);
            crypto_wipe(peer_fp_str, sizeof peer_fp_str);
        }

        /* Derive session keys */
        if (session_init(&sess, we_init, self_priv, self_pub, peer_pub,
                         sas_key) != 0) {
            LOGE("key agreement failed (bad peer key)");
            crypto_wipe(sas_key, sizeof sas_key);
            jstring reason = (*env)->NewStringUTF(env, "Key agreement failed");
            (*env)->CallVoidMethod(env, cb, mid_onHandshakeFailed, reason);
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
        (*env)->CallVoidMethod(env, cb, mid_onSasReady, sas_jstr);
    }

    /* ================================================================
     * Phase 3: Wait for SAS confirmation from Java (via pipe)
     * ================================================================ */

    {
        uint8_t hdr[3];
        if (pipe_read_exact(pipe_rd, hdr, 3) != 0) {
            LOGE("pipe read failed waiting for SAS confirm");
            jstring reason = (*env)->NewStringUTF(env, "Internal error");
            (*env)->CallVoidMethod(env, cb, mid_onDisconnected, reason);
            goto cleanup_session;
        }

        uint8_t cmd = hdr[0];
        if (cmd == CMD_QUIT) {
            LOGI("quit received during SAS wait");
            jstring reason = (*env)->NewStringUTF(env, "Session ended by user");
            (*env)->CallVoidMethod(env, cb, mid_onDisconnected, reason);
            goto cleanup_session;
        }
        if (cmd != CMD_CONFIRM_SAS) {
            LOGE("unexpected command 0x%02x during SAS wait", cmd);
            jstring reason = (*env)->NewStringUTF(env, "Unexpected command");
            (*env)->CallVoidMethod(env, cb, mid_onDisconnected, reason);
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
                    jstring reason = (*env)->NewStringUTF(env, "Peer disconnected");
                    (*env)->CallVoidMethod(env, cb, mid_onDisconnected, reason);
                    break;
                }

                if (frame_open(&sess, frame, plain, &plen) != 0) {
                    LOGE("frame_open failed (auth or sequence error)");
                    crypto_wipe(frame, sizeof frame);
                    crypto_wipe(plain, sizeof plain);
                    jstring reason = (*env)->NewStringUTF(env, "Decryption failed");
                    (*env)->CallVoidMethod(env, cb, mid_onDisconnected, reason);
                    break;
                }

                plain[plen] = '\0';
                sanitize_peer_text(plain, plen);

                jstring text = (*env)->NewStringUTF(env, (char *)plain);
                (*env)->CallVoidMethod(env, cb, mid_onMessageReceived, text);

                crypto_wipe(frame, sizeof frame);
                crypto_wipe(plain, sizeof plain);
            }

            /* --- Pipe readable: command from Java --- */
            if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
                uint8_t hdr[3];
                if (pipe_read_exact(pipe_rd, hdr, 3) != 0) {
                    LOGE("pipe read error");
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
                    jstring reason = (*env)->NewStringUTF(env, "Session ended");
                    (*env)->CallVoidMethod(env, cb, mid_onDisconnected, reason);
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
                        continue;
                    }

                    if (write_exact(fd, frame, FRAME_SZ) != 0) {
                        LOGE("write_exact failed");
                        crypto_wipe(frame, sizeof frame);
                        crypto_wipe(next_tx, sizeof next_tx);
                        crypto_wipe(msg_buf, plen);
                        (*env)->CallVoidMethod(env, cb, mid_onSendResult, (jboolean)0);
                        jstring reason = (*env)->NewStringUTF(env, "Send failed (connection lost)");
                        (*env)->CallVoidMethod(env, cb, mid_onDisconnected, reason);
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
    goto cleanup;

cleanup_session:
    /* Normal exit or post-handshake error — wipe session + keys */
    session_wipe(&sess);
    crypto_wipe(self_pub,  sizeof self_pub);
    crypto_wipe(peer_pub,  sizeof peer_pub);

cleanup:
    /* Close socket */
    if (fd != INVALID_SOCK) {
        sock_shutdown_both(fd);
        close_sock(fd);
    }

    /* Wipe and close the pipe.  Write zeros to flush any plaintext
     * command payload lingering in the kernel pipe buffer, then close
     * both ends so the kernel frees the pages. */
    {
        int wr = g_pipe_wr;
        g_pipe_wr = -1;  /* prevent races with nativePostCommand */
        if (wr >= 0) {
            uint8_t zeros[512];
            memset(zeros, 0, sizeof zeros);
            (void)write(wr, zeros, sizeof zeros);
            close(wr);
        }
    }
    close(pipe_rd);

    /* Delete the JNI global ref to the callback */
    (*env)->DeleteGlobalRef(env, cb);

    /* Detach from JVM */
    (*g_jvm)->DetachCurrentThread(g_jvm);

    g_session_active = 0;
    LOGI("session thread exiting");
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

    /* Disable core dumps — a crash must never write key material to disk. */
    struct rlimit z = {0, 0};
    setrlimit(RLIMIT_CORE, &z);

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
        jobject callback) {

    plat_init();

    /* Wait for any previous session thread to finish.  This ensures the
     * old socket is fully closed before we try to bind the same port.
     * Without this, listen→back→listen fails with "address in use". */
    if (g_session_active) {
        /* Close the listen socket to unblock accept() if still waiting */
        socket_t ls = g_listen_sock;
        if (ls != INVALID_SOCK) {
            g_listen_sock = INVALID_SOCK;
            close_sock(ls);
        }
        /* Close the pipe write end to signal quit */
        int wr = g_pipe_wr;
        g_pipe_wr = -1;
        if (wr >= 0) close(wr);
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

    /* Create the command pipe */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        LOGE("pipe() failed: %s", strerror(errno));
        return -1;
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

    /* Copy host string (connect mode only) */
    if (host) {
        const char *h = (*env)->GetStringUTFChars(env, host, NULL);
        ta->host = strdup(h);
        (*env)->ReleaseStringUTFChars(env, host, h);
    } else {
        ta->host = NULL;
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

    /* Spawn the session thread */
    /* Create joinable (not detached) so nativeStart can wait for the
     * previous thread to finish before binding the same port again. */
    int rc = pthread_create(&g_session_thread, NULL, session_thread, ta);

    if (rc != 0) {
        LOGE("pthread_create failed: %d", rc);
        (*env)->DeleteGlobalRef(env, ta->callback);
        free(ta->host);
        free(ta);
        close(pipefd[0]);
        close(pipefd[1]);
        g_pipe_wr = -1;
        return -1;
    }

    g_session_active = 1;
    LOGI("session thread spawned (mode=%d, port=%d)", (int)mode, (int)port);
    return 0;
}

/*
 * nativePostCommand — write a command to the native thread's pipe.
 *
 * Format: [cmd_byte][len_le16][payload]
 * Total size is always < PIPE_BUF so the write is atomic.
 */
JNIEXPORT void JNICALL
Java_com_example_simplecipher_ChatActivity_nativePostCommand(
        JNIEnv *env, jobject thiz, jint cmd, jbyteArray payload) {

    int wr = g_pipe_wr;
    if (wr < 0) {
        /* No active session — silently ignore. */
        return;
    }

    /* Determine payload length */
    uint16_t plen = 0;
    jbyte *pbuf = NULL;
    if (payload) {
        jsize jlen = (*env)->GetArrayLength(env, payload);
        if (jlen > MAX_MSG) {
            LOGE("nativePostCommand: payload too large (%d > %d)", (int)jlen, MAX_MSG);
            return;
        }
        plen = (uint16_t)jlen;
        pbuf = (*env)->GetByteArrayElements(env, payload, NULL);
    }

    /* Build the command buffer: [cmd(1)][len_le16(2)][payload(plen)]
     * Max total = 1 + 2 + 486 = 489, well under PIPE_BUF (4096). */
    uint8_t hdr[3];
    hdr[0] = (uint8_t)cmd;
    hdr[1] = (uint8_t)(plen & 0xFF);
    hdr[2] = (uint8_t)((plen >> 8) & 0xFF);

    /* Single atomic write: header + payload in one buffer */
    uint8_t buf[3 + MAX_MSG];
    memcpy(buf, hdr, 3);
    if (plen > 0 && pbuf) {
        memcpy(buf + 3, pbuf, plen);
    }

    ssize_t written = write(wr, buf, 3 + plen);
    if (written < 0) {
        LOGE("pipe write failed: %s", strerror(errno));
    }

    if (pbuf) {
        (*env)->ReleaseByteArrayElements(env, payload, pbuf, JNI_ABORT);
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
    if (!fp_str) return;
    if (parse_fingerprint(g_peer_fp, fp_str) == 0) {
        g_peer_fp_valid = 1;
    } else {
        LOGE("nativeSetPeerFingerprint: malformed fingerprint string");
        g_peer_fp_valid = 0;
    }
    (*env)->ReleaseStringUTFChars(env, fingerprint, fp_str);
}
