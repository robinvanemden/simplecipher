/*
 * args.c — Command-line argument parsing for SimpleCipher
 *
 * Extracts all flag handling, subcommand detection, socks5 parsing,
 * interactive connect prompts, and validation from main.c into a
 * single parse_args() call that returns a filled config_t.
 *
 * See args.h for the config_t layout and exit code definitions.
 */

#include "args.h"
#include "protocol.h"
#include "network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#    include <io.h>
#else
#    include <unistd.h>
#endif

/* ---- file-scope constants and static buffers ----------------------------- */

enum { ARGS_HOST_BUF = 256, ARGS_PORT_BUF = 8 };

/* These must survive after parse_args() returns, because config_t holds
 * pointers into them.  File-scope static keeps them alive for the
 * entire program lifetime without dynamic allocation. */
static char s5host[ARGS_HOST_BUF];
static char s5port[ARGS_PORT_BUF];
static char prompt_host[ARGS_HOST_BUF];
static char prompt_port[ARGS_PORT_BUF];

/* ---- usage ---------------------------------------------------------------- */

/* Print usage to stderr and exit. */
static void usage(const char *prog) {
    fprintf(stderr,
            "\n"
            "  SimpleCipher -- encrypted P2P chat\n"
            "\n"
            "  Usage:\n"
            "    %s listen  [--peer-fingerprint ...] [port]\n"
            "                                wait for a peer\n"
            "    %s connect [--socks5 proxy:port] [--peer-fingerprint XXXX-XXXX-XXXX-XXXX] <host> [port]\n"
            "                                connect to a peer\n"
            "    %s keygen <file>           generate persistent identity key\n"
            "\n"
            "  Options:\n"
            "    --tui                split-pane terminal interface\n"
            "    --socks5 host:port   connect through a SOCKS5 proxy (e.g. Tor)\n"
            "    --cover-traffic      hide when you type by sending constant\n"
            "                         encrypted noise (auto with --socks5;\n"
            "                         add manually when listening behind Tor)\n"
            "    --require-sandbox    abort if syscall sandbox fails to install\n"
            "    --peer-fingerprint   verify the peer's public key fingerprint\n"
            "    --trust-fingerprint  skip SAS if fingerprint matches (64-bit)\n"
            "    --identity <file>    load persistent identity key (see: keygen)\n"
            "    port                 default: 7777\n"
            "\n"
            "  After connecting, compare the safety code with your peer\n"
            "  over a separate channel (phone call, in person).\n"
#ifdef CIPHER_HARDEN
            "\n"
            "  Hardening (active in this build):\n"
            "    Memory locked, core dumps disabled, ptrace blocked.\n"
#endif
            "\n"
            "  Exit codes:\n"
            "    0  success      1  usage error    2  connection failed\n"
            "    3  handshake    4  MITM detected  5  sandbox failed\n"
            "    6  internal     7  SAS aborted\n"
            "\n",
            prog, prog, prog);
    exit(EXIT_USAGE);
}

/* ---- parse_args ----------------------------------------------------------- */

config_t parse_args(int argc, char *argv[]) {
    config_t cfg = {
        .we_init           = 0,
        .host              = nullptr,
        .port              = "7777",
        .tui_mode          = 0,
        .cover_traffic     = 0,
        .socks5_host       = nullptr,
        .socks5_port       = nullptr,
        .peer_fp_expected  = nullptr,
        .trust_fingerprint = 0,
        .identity_path     = nullptr,
        .is_keygen         = 0,
        .keygen_path       = nullptr,
    };

    const char *prog = argv[0];

    /* Parse all flags from argv in a single pass.  Flags can appear
     * anywhere — before or after the subcommand:
     *   simplecipher --tui connect --socks5 ... host
     *   simplecipher connect --peer-fingerprint ... host
     * We compact positional args (program, subcommand, host, port)
     * into the front of argv, stripping consumed flags. */
    {
        int out = 1;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--tui") == 0) {
                cfg.tui_mode = 1;
            } else if (strcmp(argv[i], "--cover-traffic") == 0) {
                cfg.cover_traffic = 1;
            } else if (strcmp(argv[i], "--require-sandbox") == 0) {
                g_require_sandbox = 1;
            } else if (strcmp(argv[i], "--version") == 0) {
                printf("SimpleCipher v%d\n", PROTOCOL_VERSION);
                exit(EXIT_OK);
            } else if (strcmp(argv[i], "--socks5") == 0 && i + 1 < argc) {
                const char *arg   = argv[++i];
                const char *colon = strrchr(arg, ':');
                if (!colon || colon == arg || !colon[1]) {
                    fprintf(stderr, "  --socks5 requires host:port format\n");
                    exit(EXIT_USAGE);
                }
                size_t hlen = (size_t)(colon - arg);
                if (hlen >= sizeof s5host) {
                    fprintf(stderr, "  socks5 host too long\n");
                    exit(EXIT_USAGE);
                }
                memcpy(s5host, arg, hlen);
                s5host[hlen] = '\0';
                snprintf(s5port, sizeof s5port, "%s", colon + 1);
                cfg.socks5_host = s5host;
                cfg.socks5_port = s5port;
                if (!validate_port(s5port)) {
                    fprintf(stderr, "  --socks5 port invalid: %s\n", s5port);
                    exit(EXIT_USAGE);
                }
            } else if (strcmp(argv[i], "--peer-fingerprint") == 0 && i + 1 < argc) {
                cfg.peer_fp_expected = argv[++i];
            } else if (strcmp(argv[i], "--trust-fingerprint") == 0) {
                cfg.trust_fingerprint = 1;
            } else if (strcmp(argv[i], "--identity") == 0 && i + 1 < argc) {
                cfg.identity_path = argv[++i];
            } else {
                argv[out++] = argv[i];
            }
        }
        argc = out;
    }

    /* --trust-fingerprint requires --peer-fingerprint.  Without a
     * fingerprint to verify, there is nothing to trust. */
    if (cfg.trust_fingerprint && !cfg.peer_fp_expected) {
        fprintf(stderr, "  --trust-fingerprint requires --peer-fingerprint\n");
        exit(EXIT_USAGE);
    }

    /* --socks5 implies --cover-traffic: if you're using Tor, you want
     * timing-correlation protection.  --cover-traffic can also be set
     * independently for listeners behind onion services or transparent
     * Tor routing (Whonix, Tails, Qubes sys-whonix). */
    if (cfg.socks5_host) cfg.cover_traffic = 1;

    if (argc < 2) usage(prog);

    /* keygen subcommand — detect early, before connect/listen dispatch. */
    if (strcmp(argv[1], "keygen") == 0) {
        if (argc < 3) {
            fprintf(stderr, "  Usage: %s keygen <output-file>\n", prog);
            exit(EXIT_USAGE);
        }
        cfg.is_keygen   = 1;
        cfg.keygen_path = argv[2];
        return cfg;
    }

    cfg.we_init = (strcmp(argv[1], "connect") == 0);
    if (!cfg.we_init && strcmp(argv[1], "listen") != 0) {
        fprintf(stderr, "  Unknown command: %s\n", argv[1]);
        usage(prog);
    }
    if (!cfg.we_init && cfg.socks5_host) {
        fprintf(stderr, "  Note: --socks5 has no effect in listen mode.\n");
        cfg.socks5_host = nullptr;
        cfg.socks5_port = nullptr;
    }

    /* Interactive connect prompt: if "connect" is given without a host,
     * prompt on stdin.  This keeps the target address out of argv, shell
     * history, and process listings — useful when connecting to sensitive
     * destinations (e.g. .onion addresses through --socks5). */
    if (cfg.we_init && argc < 3) {
        printf("  Host: ");
        fflush(stdout);
        /* read() instead of fgets() so the destination address never passes
         * through libc's internal ~4KB FILE* buffer (which is never wiped).
         * In canonical mode, read() returns a complete line from the kernel. */
        {
#if defined(_WIN32) || defined(_WIN64)
            int rn = _read(0, prompt_host, (unsigned)(sizeof prompt_host - 1));
#else
            ssize_t rn = read(STDIN_FILENO, prompt_host, sizeof prompt_host - 1);
#endif
            if (rn <= 0 || prompt_host[0] == '\n') {
                fprintf(stderr, "  No host provided.\n");
                exit(EXIT_USAGE);
            }
            prompt_host[rn] = '\0';
            /* Drain leftover bytes if input was truncated (no newline in buffer).
             * Without this, the tail spills into the port prompt. */
            {
                int had_newline = 0;
                for (int i = 0; i < rn; i++)
                    if (prompt_host[i] == '\n') {
                        had_newline = 1;
                        break;
                    }
                if (rn > 0 && prompt_host[rn - 1] == '\n') prompt_host[rn - 1] = '\0';
                if (!had_newline) {
                    char drain;
#if defined(_WIN32) || defined(_WIN64)
                    int dr;
                    do { dr = _read(0, &drain, 1); } while (dr == 1 && drain != '\n');
#else
                    ssize_t dr;
                    do { dr = read(STDIN_FILENO, &drain, 1); } while (dr == 1 && drain != '\n');
#endif
                }
            }
        }
        if (!prompt_host[0]) {
            fprintf(stderr, "  No host provided.\n");
            exit(EXIT_USAGE);
        }
        cfg.host = prompt_host;

        printf("  Port [7777]: ");
        fflush(stdout);
        {
#if defined(_WIN32) || defined(_WIN64)
            int rn = _read(0, prompt_port, (unsigned)(sizeof prompt_port - 1));
#else
            ssize_t rn = read(STDIN_FILENO, prompt_port, sizeof prompt_port - 1);
#endif
            if (rn > 0) {
                prompt_port[rn] = '\0';
                /* Drain oversized input */
                if (!memchr(prompt_port, '\n', (size_t)rn)) {
                    char drain;
#if defined(_WIN32) || defined(_WIN64)
                    int dr;
                    do { dr = _read(0, &drain, 1); } while (dr == 1 && drain != '\n');
#else
                    ssize_t dr;
                    do { dr = read(STDIN_FILENO, &drain, 1); } while (dr == 1 && drain != '\n');
#endif
                }
                if (rn > 0 && prompt_port[rn - 1] == '\n') prompt_port[rn - 1] = '\0';
                if (prompt_port[0]) cfg.port = prompt_port;
            }
        }
    } else if (cfg.we_init) {
        cfg.host = argv[2];
        if (!cfg.host[0]) {
            fprintf(stderr, "  Host cannot be empty.\n");
            exit(EXIT_USAGE);
        }
        if (argc >= 4) cfg.port = argv[3];
    } else {
        if (argc >= 3) cfg.port = argv[2];
    }
    if (!validate_port(cfg.port)) {
        fprintf(stderr, "invalid port: %s\n", cfg.port);
        exit(EXIT_USAGE);
    }

    return cfg;
}

/* Wipe static buffers that may contain sensitive data (host addresses,
 * port numbers).  Call from main() cleanup path to ensure .onion
 * addresses and other sensitive targets don't linger in process memory. */
void args_wipe(void) {
    crypto_wipe(s5host, sizeof s5host);
    crypto_wipe(s5port, sizeof s5port);
    crypto_wipe(prompt_host, sizeof prompt_host);
    crypto_wipe(prompt_port, sizeof prompt_port);
}
