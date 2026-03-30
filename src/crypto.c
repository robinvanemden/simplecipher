/*
 * crypto.c — Cryptographic operations implementation for SimpleCipher
 *
 * Implements the domain-separated hashing, key expansion, nonce
 * construction, symmetric ratchet, commitment scheme, and safety code
 * formatting declared in crypto.h.
 *
 * All crypto primitives (BLAKE2b, X25519, crypto_wipe) come from
 * Monocypher (lib/monocypher.c).
 */

#include "crypto.h"
#include "protocol.h" /* PROTOCOL_VERSION — bound into commitment hash */

static const char *const DOMAIN_COMMIT = "cipher commit v3";

#if defined(_WIN32) || defined(_WIN64)
#    include <sys/stat.h> /* chmod() fallback for key file permissions */
#    include <aclapi.h>   /* SetNamedSecurityInfoA, SetEntriesInAclA — owner-only DACL */
#else
#    include <fcntl.h>    /* open() with O_CREAT for 0600 key file permissions */
#    include <limits.h>   /* PATH_MAX */
#    include <sys/mman.h> /* mlockall/munlockall for Argon2 work buffer */
#    include <sys/stat.h> /* fstat(), chmod() for file permission check */
#    include <unistd.h>   /* fsync, unlink, close */
#endif

#ifndef PATH_MAX
#    define PATH_MAX 4096
#endif

/* Constant-time all-zero check for 32 bytes.
 *
 * Used to detect the small-subgroup attack: a crafted public key (a
 * low-order curve point) forces the X25519 output to all-zeros regardless
 * of our private key, giving an attacker a known shared secret.
 *
 * The |= accumulator reads ALL 32 bytes unconditionally -- no early exit.
 * An early-exit loop would leak the position of the first non-zero byte
 * through timing differences. */
[[nodiscard]] bool is_zero32(const uint8_t x[32]) {
    volatile uint8_t acc = 0;
    int              i;
    for (i = 0; i < 32; i++) acc |= x[i];
    return acc == 0;
}

/* Constant-time comparison of n bytes. */
[[nodiscard]] int ct_compare(const uint8_t *a, const uint8_t *b, size_t n) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff;
}

/* domain_hash: BLAKE2b keyed with a public domain label.
 *
 * Domain separation ensures that hashing the same data for different
 * protocol purposes produces unrelated outputs.  Each label ("cipher
 * commit v3", "cipher x25519 sas root v1", etc.) gives a distinct
 * output space so values cannot be confused or substituted across uses. */
void domain_hash(uint8_t out[32], const char *label, const uint8_t *msg, size_t msg_sz) {
    crypto_blake2b_keyed(out, 32, (const uint8_t *)label, strlen(label), msg, msg_sz);
}

/* expand: BLAKE2b keyed with a secret PRK, labelled output.
 *
 * Derives one named 32-byte subkey from a root pseudo-random key (PRK).
 * Each label produces an independent output, so tx_chain, rx_chain, and
 * sas_key are unrelated even though they all come from the same PRK. */
void expand(uint8_t out[32], const uint8_t prk[32], const char *label) {
    crypto_blake2b_keyed(out, 32, prk, 32, (const uint8_t *)label, strlen(label));
}

/* Build the 24-byte XChaCha20 nonce from a sequence number.
 *
 * A nonce ("number used once") is a unique value that must never be reused
 * with the same key.  Reusing a nonce with the same key breaks XChaCha20's
 * security completely -- an attacker can XOR two ciphertexts to cancel out
 * the keystream and recover plaintexts.
 *
 * Our nonce is safe because the chain key changes with every message, so
 * even though the nonce bytes are predictable (just the seq number), the
 * key they pair with is always unique -- (key, nonce) is never reused.
 * Deriving the nonce from seq avoids storing it in the frame. */
void make_nonce(uint8_t nonce[NONCE_SZ], uint64_t seq) {
    memset(nonce, 0, NONCE_SZ);
    le64_store(nonce, seq);
}

/* Advance the symmetric ratchet one step.
 *
 * Derives two values from the current chain key:
 *   mk   -- one-time message key for this frame (wipe after AEAD)
 *   next -- replacement chain key (caller stores and wipes old chain)
 *
 * Per-message forward secrecy: mk for message N is independent of mk
 * for any other message, so compromising one key reveals nothing else. */
void chain_step(const uint8_t chain[32], uint8_t mk[32], uint8_t next[32]) {
    expand(mk, chain, "mk");
    expand(next, chain, "chain");
}

/* ---- commitment scheme -------------------------------------------------- */

/* Hash our public key to produce a 32-byte commitment.
 *
 * We send this commitment BEFORE revealing the actual key.  Once sent,
 * we cannot change our key without the peer noticing a mismatch.
 *
 * WHY THIS IS NECESSARY:
 * Without commitment, a man-in-the-middle (Mallory) could:
 *   1. Intercept Alice's key A.
 *   2. Wait to see Bob's key B.
 *   3. Search for a fake B' so SAS(DH(a, B'), A, B') matches Bob's SAS.
 *      Because the SAS is short and human-readable, this search succeeds
 *      in milliseconds.
 *
 * With commitment, Mallory must commit to her fake keys before she sees
 * A or B.  She cannot adapt after the fact, so the search attack fails. */
void make_commit(uint8_t commit[KEY], const uint8_t pub[KEY], const uint8_t nonce[KEY]) {
    uint8_t buf[KEY * 2 + 1]; /* pub || nonce || version_byte */
    memcpy(buf, pub, KEY);
    memcpy(buf + KEY, nonce, KEY);
    buf[KEY * 2] = (uint8_t)PROTOCOL_VERSION;
    domain_hash(commit, DOMAIN_COMMIT, buf, sizeof buf);
    crypto_wipe(buf, sizeof buf);
}

/* Verify a revealed public key against a previously received commitment.
 * Returns 1 if the key matches the commitment, 0 otherwise.
 * Uses constant-time comparison (consistent policy; costs nothing). */
[[nodiscard]] int verify_commit(const uint8_t commit[KEY], const uint8_t pub[KEY], const uint8_t nonce[KEY]) {
    uint8_t expected[KEY];
    uint8_t buf[KEY * 2 + 1]; /* pub || nonce || version_byte */
    memcpy(buf, pub, KEY);
    memcpy(buf + KEY, nonce, KEY);
    buf[KEY * 2] = (uint8_t)PROTOCOL_VERSION;
    domain_hash(expected, DOMAIN_COMMIT, buf, sizeof buf);
    int ok = (crypto_verify32(expected, commit) == 0);
    crypto_wipe(expected, sizeof expected);
    crypto_wipe(buf, sizeof buf);
    return ok;
}

/* Format 4 bytes of the SAS key as "AAAA-BBBB" for out-of-band comparison.
 *
 * 32 bits is sufficient because commitment prevents brute-forcing: Mallory
 * cannot search for a matching code after committing.  The hex format reads
 * clearly over a voice call: "A-3-F-2 dash 9-1-B-C". */
void format_sas(char out[SAS_STR_SZ], const uint8_t key[KEY]) {
    /* "XXXX-XXXX" = 9 chars + NUL = 10 bytes; SAS_STR_SZ = 20 (oversized). */
    static_assert(SAS_STR_SZ >= 10);
    snprintf(out, SAS_STR_SZ, "%02X%02X-%02X%02X", key[0], key[1], key[2], key[3]);
}

/* Format a public key fingerprint as "XXXX-XXXX-XXXX-XXXX" (16 hex chars).
 *
 * Hashes the public key with a distinct domain label, then formats the first
 * 8 bytes (64 bits) as four dash-separated groups of 4 hex digits.  64 bits
 * provides ~2^64 second-preimage resistance against offline key generation
 * (an attacker trying to forge a matching fingerprint).  The commitment
 * scheme protects the 32-bit SAS against online brute-force during a
 * session, but does not apply to the pre-shared fingerprint.
 *
 * The fingerprint lets users verify peer identity out-of-band (paper, QR code,
 * Signal) before the session starts, adding a second layer of trust beyond
 * the in-session SAS code. */
void format_fingerprint(char out[FINGERPRINT_STR_SZ], const uint8_t pub[KEY]) {
    /* "XXXX-XXXX-XXXX-XXXX" = 19 chars + NUL = 20 bytes. */
    static_assert(FINGERPRINT_STR_SZ >= 20);
    uint8_t hash[32];
    domain_hash(hash, "cipher fingerprint v2", pub, KEY);
    snprintf(out, FINGERPRINT_STR_SZ, "%02X%02X-%02X%02X-%02X%02X-%02X%02X", hash[0], hash[1], hash[2], hash[3],
             hash[4], hash[5], hash[6], hash[7]);
    crypto_wipe(hash, sizeof hash);
}

/* ---- Persistent identity keys ------------------------------------------- */

/* Argon2id parameters: ~100 MB memory, 3 passes, single-threaded.
 * Stretches a human-chosen passphrase into a 32-byte encryption key.
 * ~0.5-1 second on modern hardware; makes GPU brute-force expensive. */
static const crypto_argon2_config identity_kdf_config = {.algorithm = CRYPTO_ARGON2_ID,
                                                         .nb_blocks = 100000, /* ~100 MB */
                                                         .nb_passes = 3,
                                                         .nb_lanes  = 1};

/* Derive an encryption key from a passphrase and salt.
 * Returns 0 on success, -1 on allocation failure. */
static int identity_kdf(uint8_t enc_key[KEY], const uint8_t salt[IDENTITY_SALT_SZ], const char *pass, size_t pass_len) {
    if (pass_len > UINT32_MAX) return -1;
    size_t work_sz    = (size_t)identity_kdf_config.nb_blocks * 1024;
    int    did_unlock = 0;
    void  *work       = malloc(work_sz);
#if !defined(_WIN32) && !defined(_WIN64)
    /* mlockall(MCL_FUTURE) (set by harden()) forces every allocation to be
     * locked into RAM.  On systems with a low RLIMIT_MEMLOCK the ~100 MB
     * Argon2 work buffer allocation fails because malloc triggers mmap which
     * cannot lock the new pages.
     *
     * Old approach: munlockall() dropped ALL locks, making passphrases and
     * identity keys in memory pageable to disk during KDF computation.
     *
     * New approach: munlockall() + mlockall(MCL_CURRENT) keeps every existing
     * page locked (secrets stay in RAM) but removes MCL_FUTURE so the next
     * malloc can allocate unlocked pages.  After Argon2 finishes and the work
     * buffer is freed, we restore MCL_CURRENT | MCL_FUTURE.  The work buffer
     * itself is not security-sensitive — it holds intermediate Argon2 state
     * that is useless without the passphrase. */
    if (!work) {
        /* Lift MCL_FUTURE so the large allocation can succeed.
         * Re-lock existing pages immediately to keep secrets in RAM.
         * On systems with very low RLIMIT_MEMLOCK (OpenBSD), MCL_CURRENT
         * may fail — secrets are briefly pageable but we re-lock after
         * the work buffer is freed. */
        munlockall();
        did_unlock = 1;
        work       = malloc(work_sz);
        if (work && mlockall(MCL_CURRENT) != 0) /* re-lock existing pages */
            fprintf(stderr, "warning: mlockall failed — keys may be swapped to disk\n");
    }
#endif
    if (!work) {
        crypto_wipe(enc_key, KEY);
#if !defined(_WIN32) && !defined(_WIN64)
        if (did_unlock && mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
            fprintf(stderr, "warning: mlockall restore failed — keys may be swapped to disk\n");
#endif
        return -1;
    }

    crypto_argon2_inputs inputs = {
        .pass = (const uint8_t *)pass, .salt = salt, .pass_size = (uint32_t)pass_len, .salt_size = IDENTITY_SALT_SZ};
    crypto_argon2(enc_key, KEY, work, identity_kdf_config, inputs, crypto_argon2_no_extras);
    crypto_wipe(work, work_sz);
    free(work);
#if !defined(_WIN32) && !defined(_WIN64)
    if (did_unlock && mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
        fprintf(stderr, "warning: mlockall restore failed — keys may be swapped to disk\n");
#endif
    return 0;
}

/* Save an encrypted identity key to a file.
 *
 * Atomic write guarantee (POSIX): writes to a temp file (path + ".tmp"),
 * fsyncs, then rename()s over the target.  If any step fails, only the
 * temp file is removed — the original file is never modified.  This
 * prevents data loss if the process is killed or the disk fills up
 * mid-write.  After rename, chmod ensures 0600 even if the directory
 * has a permissive umask or the file previously had looser permissions.
 *
 * On Windows: writes to a temp file (GetTempFileNameA), then replaces
 * via MoveFileExA(MOVEFILE_REPLACE_EXISTING); _chmod tightens permissions. */
int identity_save(const char *path, const uint8_t priv[KEY], const char *pass, size_t pass_len) {
    uint8_t salt[IDENTITY_SALT_SZ], nonce[NONCE_SZ];
    fill_random(salt, sizeof salt);
    fill_random(nonce, sizeof nonce);

    uint8_t enc_key[KEY];
    if (identity_kdf(enc_key, salt, pass, pass_len) != 0) return -1;

    uint8_t ct[KEY], mac[MAC_SZ];
    crypto_aead_lock(ct, mac, enc_key, nonce, NULL, 0, priv, KEY);
    crypto_wipe(enc_key, sizeof enc_key);

#if defined(_WIN32) || defined(_WIN64)
    /* Write to a temp file in the same directory, then atomically replace
     * the target.  Mirrors the POSIX path below. */
    char dir[MAX_PATH], tmp_path[MAX_PATH];

    /* Extract parent directory from path. */
    {
        const char *slash  = strrchr(path, '\\');
        const char *fslash = strrchr(path, '/');
        if (fslash && (!slash || fslash > slash)) slash = fslash;
        if (slash) {
            size_t dlen = (size_t)(slash - path);
            if (dlen >= sizeof dir) {
                crypto_wipe(ct, sizeof ct);
                return -1;
            }
            memcpy(dir, path, dlen);
            dir[dlen] = '\0';
        } else {
            dir[0] = '.';
            dir[1] = '\0';
        }
    }

    if (GetTempFileNameA(dir, "sci", 0, tmp_path) == 0) {
        crypto_wipe(ct, sizeof ct);
        return -1;
    }

    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        DeleteFileA(tmp_path);
        crypto_wipe(ct, sizeof ct);
        return -1;
    }

    int ok = (fwrite(salt, 1, sizeof salt, f) == sizeof salt && fwrite(nonce, 1, sizeof nonce, f) == sizeof nonce &&
              fwrite(ct, 1, sizeof ct, f) == sizeof ct && fwrite(mac, 1, sizeof mac, f) == sizeof mac);
    int flush_ok = (fflush(f) == 0);
    int close_ok = (fclose(f) == 0);
    crypto_wipe(ct, sizeof ct);

    if (!ok || !flush_ok || !close_ok) {
        DeleteFileA(tmp_path);
        return -1;
    }

    /* Atomic replace: the original file is untouched until this succeeds. */
    if (!MoveFileExA(tmp_path, path, MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileA(tmp_path);
        return -1;
    }

    /* Set owner-only DACL.  _chmod(0600) on Windows only sets the DOS
     * read-only attribute, not a real ACL.  We use SetNamedSecurityInfoA
     * to create a DACL with a single ACE granting the owner full control. */
    {
        HANDLE token = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            TOKEN_USER *tu      = NULL;
            DWORD       tu_size = 0;
            GetTokenInformation(token, TokenUser, NULL, 0, &tu_size);
            tu = (TOKEN_USER *)malloc(tu_size);
            if (tu && GetTokenInformation(token, TokenUser, tu, tu_size, &tu_size)) {
                EXPLICIT_ACCESS_A ea    = {0};
                ea.grfAccessPermissions = GENERIC_ALL;
                ea.grfAccessMode        = SET_ACCESS;
                ea.grfInheritance       = NO_INHERITANCE;
                ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
                ea.Trustee.ptstrName    = (LPSTR)tu->User.Sid;
                PACL acl                = NULL;
                if (SetEntriesInAclA(1, &ea, NULL, &acl) == ERROR_SUCCESS) {
                    SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT,
                                          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL,
                                          acl, NULL);
                    LocalFree(acl);
                }
            }
            free(tu);
            CloseHandle(token);
        }
    }
    crypto_wipe(mac, sizeof mac);
    crypto_wipe(salt, sizeof salt);
    crypto_wipe(nonce, sizeof nonce);
    return 0;
#else
    /* Build temp path in the same directory for atomic rename.
     * PATH_MAX covers any realistic path; overflow is checked below. */
    static_assert(PATH_MAX >= 256);
    char tmp_path[PATH_MAX];
    int  n = snprintf(tmp_path, sizeof tmp_path, "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof tmp_path) {
        crypto_wipe(ct, sizeof ct);
        return -1;
    }

    /* Remove stale .tmp from a previous crashed save, but only if it is
     * a regular file (lstat + S_ISREG) — never follow symlinks here. */
    {
        struct stat st;
        if (lstat(tmp_path, &st) == 0 && S_ISREG(st.st_mode)) unlink(tmp_path);
    }

    /* O_EXCL prevents following a symlink-planted .tmp file. */
    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW | O_EXCL, 0600);
    if (fd < 0) {
        crypto_wipe(ct, sizeof ct);
        return -1;
    }
    FILE *f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        unlink(tmp_path);
        crypto_wipe(ct, sizeof ct);
        return -1;
    }

    int ok = (fwrite(salt, 1, sizeof salt, f) == sizeof salt && fwrite(nonce, 1, sizeof nonce, f) == sizeof nonce &&
              fwrite(ct, 1, sizeof ct, f) == sizeof ct && fwrite(mac, 1, sizeof mac, f) == sizeof mac);

    /* fsync before rename to ensure data is on disk. */
    int sync_ok  = (fsync(fileno(f)) == 0);
    int close_ok = (fclose(f) == 0);

    if (!ok || !sync_ok || !close_ok) {
        unlink(tmp_path);
        crypto_wipe(ct, sizeof ct);
        return -1;
    }

    /* Atomic replace: the original file is untouched until this succeeds. */
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        crypto_wipe(ct, sizeof ct);
        return -1;
    }

    /* fsync the parent directory to make the rename durable on ext4
     * data=writeback and similar configurations. */
    {
        char        dir[PATH_MAX];
        const char *slash = strrchr(path, '/');
        if (slash) {
            memcpy(dir, path, (size_t)(slash - path));
            dir[slash - path] = '\0';
        } else {
            dir[0] = '.';
            dir[1] = '\0';
        }
        int dfd = open(dir, O_RDONLY);
        if (dfd >= 0) {
            fsync(dfd);
            close(dfd);
        }
    }

    chmod(path, 0600);
    crypto_wipe(ct, sizeof ct);
    crypto_wipe(mac, sizeof mac);
    crypto_wipe(salt, sizeof salt);
    crypto_wipe(nonce, sizeof nonce);
    return 0;
#endif
}

int identity_load(const char *path, uint8_t priv[KEY], uint8_t pub[KEY], const char *pass, size_t pass_len) {
    /* O_NOFOLLOW prevents opening a symlink-planted identity file.
     * identity_save already uses O_NOFOLLOW; this closes the asymmetry.
     * On FreeBSD /tmp is often a symlink to /var/tmp, so we only enforce
     * O_NOFOLLOW on Linux where seccomp cannot block symlink-based attacks.
     * FreeBSD (Capsicum) and OpenBSD (pledge) handle this at the OS level. */
#if defined(__linux__)
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "rb");
    if (!f) {
        close(fd);
        return -1;
    }
#else
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
#endif
#if !defined(_WIN32) && !defined(_WIN64)
    {
        struct stat st;
        if (fstat(fileno(f), &st) == 0 && (st.st_mode & 0077) != 0)
            fprintf(stderr, "warning: %s has permissive permissions — consider chmod 600\n", path);
    }
#endif

    uint8_t buf[IDENTITY_FILE_SZ];
    size_t  n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n != IDENTITY_FILE_SZ) {
        crypto_wipe(buf, sizeof buf);
        return -1;
    }

    const uint8_t *salt  = buf;
    const uint8_t *nonce = buf + IDENTITY_SALT_SZ;
    const uint8_t *ct    = buf + IDENTITY_SALT_SZ + NONCE_SZ;
    const uint8_t *mac   = buf + IDENTITY_SALT_SZ + NONCE_SZ + KEY;

    uint8_t enc_key[KEY];
    if (identity_kdf(enc_key, salt, pass, pass_len) != 0) {
        crypto_wipe(buf, sizeof buf);
        return -1;
    }

    int ok = crypto_aead_unlock(priv, mac, enc_key, nonce, NULL, 0, ct, KEY);
    crypto_wipe(enc_key, sizeof enc_key);
    crypto_wipe(buf, sizeof buf);

    if (ok != 0) {
        crypto_wipe(priv, KEY);
        return -1;
    }

    crypto_x25519_public_key(pub, priv);
    return 0;
}
