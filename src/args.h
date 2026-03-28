/*
 * args.h — Command-line argument parsing for SimpleCipher
 *
 * This module handles all flag and subcommand parsing: --tui, --socks5,
 * --cover-traffic, --peer-fingerprint, --trust-fingerprint, --identity,
 * --require-sandbox, --version, and the connect / listen / keygen
 * subcommands.  It also handles the interactive connect prompt (host/port
 * from stdin when "connect" is given without a target).
 *
 * parse_args() returns a filled config_t and never returns on usage errors
 * (it prints help and exits with EXIT_USAGE).
 *
 * Read next: main.c (session lifecycle that consumes config_t)
 */

#ifndef SIMPLECIPHER_ARGS_H
#define SIMPLECIPHER_ARGS_H

/* Exit codes — distinct values let scripts distinguish failure types. */
enum {
    EXIT_OK        = 0,
    EXIT_USAGE     = 1,
    EXIT_NET       = 2,
    EXIT_HANDSHAKE = 3,
    EXIT_MITM      = 4,
    EXIT_SANDBOX   = 5,
    EXIT_INTERNAL  = 6,
    EXIT_ABORT     = 7,
};

/* Parsed command-line configuration. */
typedef struct {
    int         we_init;           /* 1 = connect (initiator), 0 = listen */
    const char *host;              /* connect target (NULL in listen mode) */
    const char *port;              /* default "7777" */
    int         tui_mode;          /* --tui */
    int         cover_traffic;     /* --cover-traffic (auto with --socks5) */
    const char *socks5_host;       /* --socks5 host part */
    const char *socks5_port;       /* --socks5 port part */
    const char *peer_fp_expected;  /* --peer-fingerprint value */
    int         trust_fingerprint; /* --trust-fingerprint */
    const char *identity_path;     /* --identity file path */
    int         is_keygen;         /* 1 if "keygen" subcommand */
    const char *keygen_path;       /* output file for keygen */
} config_t;

/* Parse command-line arguments into a config_t.
 * Handles --version (prints and exits) and --help/bad args (prints usage, exits).
 * The returned config is fully validated. */
config_t parse_args(int argc, char *argv[]);

/* Wipe static buffers that hold sensitive data (host addresses, ports).
 * Call from main() cleanup path. */
void args_wipe(void);

#endif /* SIMPLECIPHER_ARGS_H */
