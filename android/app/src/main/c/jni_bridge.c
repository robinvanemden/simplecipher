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
        /* Listen mode */
        LOGI("listening on port %s", port_str);
        fd = listen_socket(port_str);
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

        gen_keypair(self_priv, self_pub);
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
                    if (frame_build(sess.tx, sess.tx_seq,
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

    /* Close pipe read end */
    close(pipe_rd);

    /* Reset global pipe write fd so stale nativePostCommand calls are no-ops */
    g_pipe_wr = -1;

    /* Delete the JNI global ref to the callback */
    (*env)->DeleteGlobalRef(env, cb);

    /* Detach from JVM */
    (*g_jvm)->DetachCurrentThread(g_jvm);

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

    /* Verify all method IDs resolved */
    if (!ta->mid_onConnected || !ta->mid_onConnectionFailed ||
        !ta->mid_onSasReady || !ta->mid_onHandshakeFailed ||
        !ta->mid_onMessageReceived || !ta->mid_onSendResult ||
        !ta->mid_onDisconnected) {
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
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    int rc = pthread_create(&tid, &attr, session_thread, ta);
    pthread_attr_destroy(&attr);

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
