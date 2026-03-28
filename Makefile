CC      ?= gcc

# Security-critical flags — always applied, cannot be overridden.
# CIPHER_HARDEN enables mlockall, core dump suppression, ptrace blocking,
# and seccomp/Capsicum/pledge sandboxing.
SECURITY_CFLAGS = -DCIPHER_HARDEN -DNDEBUG \
                  -fstack-protector-strong \
                  -ftrivial-auto-var-init=zero \
                  -fvisibility=hidden \
                  -fno-delete-null-pointer-checks \
                  -fno-strict-overflow \
                  -fno-strict-aliasing \
                  -fstrict-flex-arrays=3

# User-overridable flags (optimization, warnings, includes).
CFLAGS  ?= -Os -std=c23 -Wall -Wextra -Wformat=2 -Wconversion -Wimplicit-fallthrough \
           -Wbidi-chars=any \
           -Werror=format-security -Werror=incompatible-pointer-types -Werror=int-conversion \
           -Isrc -Ilib \
           -flto -ffunction-sections -fdata-sections -fmerge-all-constants

# Combined: security flags are prepended and cannot be removed by overriding CFLAGS.
ALL_CFLAGS = $(SECURITY_CFLAGS) $(CFLAGS)

LDFLAGS ?= -flto -Wl,--gc-sections -s

# Core sources (platform-independent + small inline #ifdefs)
CORE_SRC = src/platform.c src/crypto.c src/protocol.c src/ratchet.c src/network.c \
           src/tui.c src/cli.c src/args.c src/verify.c lib/monocypher.c

# Platform-specific event loops and hardening
UNAME := $(shell uname -s)
ifeq ($(UNAME),Linux)
  PLAT_SRC = src/tui_posix.c src/cli_posix.c
  CFLAGS  += -fstack-clash-protection -D_FORTIFY_SOURCE=3
  LDFLAGS += -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,nodlopen
else ifeq ($(UNAME),Darwin)
  PLAT_SRC = src/tui_posix.c src/cli_posix.c
else ifeq ($(UNAME),OpenBSD)
  PLAT_SRC = src/tui_posix.c src/cli_posix.c
else ifeq ($(UNAME),FreeBSD)
  PLAT_SRC = src/tui_posix.c src/cli_posix.c
else
  PLAT_SRC = src/tui_win.c src/cli_win.c
  LDFLAGS += -lws2_32 -lbcrypt -liphlpapi
endif

SRC = src/main.c $(CORE_SRC) $(PLAT_SRC)
OBJ = $(SRC:.c=.o)

simplecipher: $(OBJ)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

# Suppress -Wconversion for vendored Monocypher (upstream code, do not modify)
lib/monocypher.o: lib/monocypher.c
	$(CC) $(ALL_CFLAGS) -Wno-conversion -c -o $@ $<

test: tests/test_p2p
	./tests/test_p2p

test-socks5: tests/test_socks5_proxy
	./tests/test_socks5_proxy

LIB_OBJ = $(filter-out src/main.o,$(OBJ))
tests/test_p2p: tests/test_p2p.c $(LIB_OBJ)
	$(CC) $(ALL_CFLAGS) -pthread -o $@ $^

tests/test_socks5_proxy: tests/test_socks5_proxy.c $(LIB_OBJ)
	$(CC) $(ALL_CFLAGS) -pthread -o $@ $^

clean:
	rm -f $(OBJ) simplecipher tests/test_p2p tests/test_socks5_proxy

.PHONY: test clean
