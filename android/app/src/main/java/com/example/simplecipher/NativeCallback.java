package com.example.simplecipher;

/**
 * Callback interface for the native SimpleCipher session thread.
 *
 * The native layer runs a single POSIX thread that owns all crypto,
 * session, and socket state.  Java communicates with it via a command
 * pipe (see jni_bridge.c).  Results come back through these callbacks.
 *
 * All methods are called FROM the native thread via JNI CallVoidMethod.
 * Implementations must post UI work to the main thread via a Handler.
 */
public interface NativeCallback {
    /** TCP connection established (connect or accept succeeded). */
    void onConnected();

    /** TCP connection failed (DNS, timeout, port in use, etc.). */
    void onConnectionFailed(String reason);

    /** Handshake complete; SAS code ready for user verification. */
    void onSasReady(String code);

    /** Handshake failed (version mismatch, commitment mismatch, bad key). */
    void onHandshakeFailed(String reason);

    /** Decrypted peer message received. */
    void onMessageReceived(String text);

    /** Result of a CMD_SEND command. */
    void onSendResult(boolean ok);

    /** Session ended (peer disconnect, error, or CMD_QUIT processed). */
    void onDisconnected(String reason);
}
