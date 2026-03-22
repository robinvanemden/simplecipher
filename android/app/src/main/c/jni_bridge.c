/*
 * jni_bridge.c — Android JNI bridge for SimpleCipher P2P encrypted chat.
 *
 * Links against the modular SimpleCipher library (platform, crypto,
 * protocol, network) and exposes JNI functions for connect, listen,
 * handshake, send, receive, disconnect.
 */

#include "platform.h"
#include "crypto.h"
#include "protocol.h"
#include "network.h"

#include <jni.h>
#include <android/log.h>

#define TAG "SimpleCipher"
#ifdef NDEBUG
/* Release: suppress all logging to prevent leaking sensitive data to logcat */
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#endif

/* Session state — mirrors the desktop globals.
 *
 * THREADING MODEL
 * ===============
 * The Java side spawns separate threads for handshake, each send, receive,
 * and disconnect (ChatActivity.java).  All of them touch the same globals
 * below (jni_fd, jni_sess, key material).  Without serialization:
 *   - Two send threads can read the same (chain key, seq) before either
 *     commits the update, reusing a (key, nonce) pair.  For XChaCha20-
 *     Poly1305 that completely breaks confidentiality.
 *   - A disconnect thread can close jni_fd while send/receive are mid-
 *     syscall, or wipe jni_sess while frame_build is reading it.
 *
 * jni_lock serializes ALL JNI calls that touch shared state.  This is
 * coarse-grained (one lock for everything) but correct and simple.  The
 * critical sections are short (one frame encrypt + one send syscall) so
 * contention is negligible for a chat application. */
static socket_t     jni_fd      = INVALID_SOCK;
static session_t    jni_sess;
static int          jni_we_init = 0;
static uint8_t      jni_self_priv[KEY], jni_self_pub[KEY], jni_peer_pub[KEY];

#include <pthread.h>
static pthread_mutex_t jni_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- JNI helpers -------------------------------------------------------- */

static jstring jstr(JNIEnv *env, const char *s) {
    return (*env)->NewStringUTF(env, s);
}

/* ---- JNI exports -------------------------------------------------------- */

JNIEXPORT jint JNICALL
Java_com_example_simplecipher_ChatActivity_nativeInit(JNIEnv *env, jobject thiz) {
    plat_init();
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_example_simplecipher_ChatActivity_nativeConnect(
        JNIEnv *env, jobject thiz, jstring host, jint port) {
    const char *h = (*env)->GetStringUTFChars(env, host, NULL);
    char p[6];
    snprintf(p, sizeof p, "%d", (int)port);

    LOGI("connecting to %s:%s", h, p);
    pthread_mutex_lock(&jni_lock);
    jni_fd = connect_socket(h, p);
    (*env)->ReleaseStringUTFChars(env, host, h);

    if (jni_fd == INVALID_SOCK) {
        LOGE("connect failed");
        pthread_mutex_unlock(&jni_lock);
        return -1;
    }
    jni_we_init = 1;
    pthread_mutex_unlock(&jni_lock);
    LOGI("connected");
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_example_simplecipher_ChatActivity_nativeListen(
        JNIEnv *env, jobject thiz, jint port) {
    char p[6];
    snprintf(p, sizeof p, "%d", (int)port);

    LOGI("listening on port %s", p);
    pthread_mutex_lock(&jni_lock);
    jni_fd = listen_socket(p);

    if (jni_fd == INVALID_SOCK) {
        LOGE("listen/accept failed");
        pthread_mutex_unlock(&jni_lock);
        return -1;
    }
    jni_we_init = 0;
    pthread_mutex_unlock(&jni_lock);
    LOGI("peer connected");
    return 0;
}

JNIEXPORT jstring JNICALL
Java_com_example_simplecipher_ChatActivity_nativeHandshake(
        JNIEnv *env, jobject thiz) {
    uint8_t commit_self[KEY], commit_peer[KEY];
    uint8_t sas_key[KEY];
    char    sas[20];
    jstring result;

    pthread_mutex_lock(&jni_lock);

    gen_keypair(jni_self_priv, jni_self_pub);
    make_commit(commit_self, jni_self_pub);

    set_sock_timeout(jni_fd, 30);

    /* Version exchange */
    {
        uint8_t my_ver = (uint8_t)PROTOCOL_VERSION;
        uint8_t peer_ver = 0;
        if (exchange(jni_fd, jni_we_init, &my_ver, 1, &peer_ver, 1) != 0) {
            LOGE("handshake error (version exchange)");
            goto fail;
        }
        if (peer_ver != PROTOCOL_VERSION) {
            LOGE("version mismatch: we=%d peer=%d", PROTOCOL_VERSION, (int)peer_ver);
            goto fail;
        }
    }

    /* Commitment exchange */
    if (exchange(jni_fd, jni_we_init, commit_self, KEY, commit_peer, KEY) != 0) {
        LOGE("handshake error (commitments)");
        goto fail;
    }

    /* Key reveal */
    if (exchange(jni_fd, jni_we_init, jni_self_pub, KEY, jni_peer_pub, KEY) != 0) {
        LOGE("handshake error (keys)");
        goto fail;
    }

    set_sock_timeout(jni_fd, 0);

    /* Verify commitment */
    if (!verify_commit(commit_peer, jni_peer_pub)) {
        LOGE("commitment mismatch -- possible MITM");
        goto fail;
    }

    crypto_wipe(commit_self, sizeof commit_self);
    crypto_wipe(commit_peer, sizeof commit_peer);

    /* Derive session keys */
    if (session_init(&jni_sess, jni_we_init,
                     jni_self_priv, jni_self_pub, jni_peer_pub,
                     sas_key) != 0) {
        LOGE("key agreement failed (bad peer key)");
        goto fail;
    }
    crypto_wipe(jni_self_priv, sizeof jni_self_priv);

    /* No chat-phase timeout.  Unlike desktop (where poll() returns only
     * when data has started arriving and SO_RCVTIMEO catches stalled partial
     * frames), the Android JNI blocks in read_exact() directly.  A timeout
     * here would tear down healthy idle sessions after 30 seconds of silence.
     * The handshake timeout (set above) protects the handshake phase. */

    format_sas(sas, sas_key);
    crypto_wipe(sas_key, sizeof sas_key);

    LOGI("handshake complete");
    result = jstr(env, sas);
    crypto_wipe(sas, sizeof sas);
    pthread_mutex_unlock(&jni_lock);
    return result;

fail:
    /* Clean up fully on handshake failure: close the socket and wipe all
     * session state.  Without this, stale keys and an open socket linger
     * until the activity is eventually destroyed. */
    if (jni_fd != INVALID_SOCK) {
        sock_shutdown_both(jni_fd);
        close_sock(jni_fd);
        jni_fd = INVALID_SOCK;
    }
    session_wipe(&jni_sess);
    crypto_wipe(commit_self,   sizeof commit_self);
    crypto_wipe(commit_peer,   sizeof commit_peer);
    crypto_wipe(sas_key,       sizeof sas_key);
    crypto_wipe(sas,           sizeof sas);
    crypto_wipe(jni_self_priv, sizeof jni_self_priv);
    crypto_wipe(jni_self_pub,  sizeof jni_self_pub);
    crypto_wipe(jni_peer_pub,  sizeof jni_peer_pub);
    pthread_mutex_unlock(&jni_lock);
    return jstr(env, "");
}

JNIEXPORT jint JNICALL
Java_com_example_simplecipher_ChatActivity_nativeConfirmSas(
        JNIEnv *env, jobject thiz) {
    /* SAS confirmed by user — session is now active. */
    LOGI("SAS confirmed, session active");
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_example_simplecipher_ChatActivity_nativeSend(
        JNIEnv *env, jobject thiz, jstring msg) {
    const char *m = (*env)->GetStringUTFChars(env, msg, NULL);
    size_t len = strlen(m);
    uint8_t frame[FRAME_SZ], next_tx[KEY];
    int rc = -1;

    if (len > (size_t)MAX_MSG) {
        LOGE("message too long (%zu > %d)", len, MAX_MSG);
        goto done;
    }

    pthread_mutex_lock(&jni_lock);

    if (frame_build(jni_sess.tx, jni_sess.tx_seq,
                    (const uint8_t *)m, (uint16_t)len,
                    frame, next_tx) != 0) {
        LOGE("frame_build failed");
        pthread_mutex_unlock(&jni_lock);
        goto done;
    }

    if (write_exact(jni_fd, frame, FRAME_SZ) != 0) {
        LOGE("send failed");
        pthread_mutex_unlock(&jni_lock);
        goto done;
    }

    /* Commit chain advance after successful send */
    memcpy(jni_sess.tx, next_tx, KEY);
    jni_sess.tx_seq++;
    pthread_mutex_unlock(&jni_lock);
    rc = 0;

done:
    (*env)->ReleaseStringUTFChars(env, msg, m);
    crypto_wipe(frame, sizeof frame);
    crypto_wipe(next_tx, sizeof next_tx);
    return rc;
}

JNIEXPORT jstring JNICALL
Java_com_example_simplecipher_ChatActivity_nativeReceive(
        JNIEnv *env, jobject thiz) {
    uint8_t  frame[FRAME_SZ];
    uint8_t  plain[MAX_MSG + 1];
    uint16_t plen = 0;

    /* read_exact blocks waiting for a full frame.  We do NOT hold jni_lock
     * here: that would prevent sends from proceeding while we wait.  This
     * is safe because only one receive thread runs at a time (Java side
     * creates a single receive loop in startReceiveLoop). */
    if (read_exact(jni_fd, frame, FRAME_SZ) != 0) {
        crypto_wipe(frame, sizeof frame);
        return NULL;  /* peer disconnected */
    }

    /* Lock for frame_open: it mutates jni_sess.rx and jni_sess.rx_seq.
     * A concurrent disconnect could wipe jni_sess mid-operation. */
    pthread_mutex_lock(&jni_lock);
    if (frame_open(&jni_sess, frame, plain, &plen) != 0) {
        LOGE("frame_open failed (auth or sequence error)");
        pthread_mutex_unlock(&jni_lock);
        crypto_wipe(frame, sizeof frame);
        crypto_wipe(plain, sizeof plain);
        return NULL;
    }
    pthread_mutex_unlock(&jni_lock);

    plain[plen] = '\0';
    sanitize_peer_text(plain, plen);

    jstring result = jstr(env, (char *)plain);
    crypto_wipe(frame, sizeof frame);
    crypto_wipe(plain, sizeof plain);
    return result;
}

JNIEXPORT void JNICALL
Java_com_example_simplecipher_ChatActivity_nativeDisconnect(
        JNIEnv *env, jobject thiz) {
    pthread_mutex_lock(&jni_lock);
    if (jni_fd != INVALID_SOCK) {
        sock_shutdown_both(jni_fd);
        close_sock(jni_fd);
        jni_fd = INVALID_SOCK;
    }
    session_wipe(&jni_sess);
    crypto_wipe(jni_self_priv, sizeof jni_self_priv);
    crypto_wipe(jni_self_pub, sizeof jni_self_pub);
    crypto_wipe(jni_peer_pub, sizeof jni_peer_pub);
    pthread_mutex_unlock(&jni_lock);
    LOGI("disconnected and wiped");
}
