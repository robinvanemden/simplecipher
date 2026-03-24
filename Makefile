CC      ?= gcc

# Security-hardened flags matching the CMake release build.
# Override with: make CFLAGS="..." for a custom build.
CFLAGS  ?= -Os -std=c23 -Wall -Wextra -Wformat=2 -Wconversion -Wimplicit-fallthrough \
           -Wbidi-chars=any \
           -Werror=format-security -Werror=incompatible-pointer-types -Werror=int-conversion \
           -Isrc -Ilib \
           -flto -ffunction-sections -fdata-sections -fmerge-all-constants \
           -fstack-protector-strong \
           -ftrivial-auto-var-init=zero \
           -fvisibility=hidden \
           -fno-delete-null-pointer-checks \
           -fno-strict-overflow \
           -fno-strict-aliasing \
           -fstrict-flex-arrays=3 \
           -DNDEBUG -DCIPHER_HARDEN

LDFLAGS ?= -flto -Wl,--gc-sections -s

# Core sources (platform-independent + small inline #ifdefs)
CORE_SRC = src/platform.c src/crypto.c src/protocol.c src/ratchet.c src/network.c \
           src/tui.c src/cli.c lib/monocypher.c

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
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Suppress -Wconversion for vendored Monocypher (upstream code, do not modify)
lib/monocypher.o: lib/monocypher.c
	$(CC) $(CFLAGS) -Wno-conversion -c -o $@ $<

test: tests/test_p2p
	./tests/test_p2p

LIB_OBJ = $(filter-out src/main.o,$(OBJ))
tests/test_p2p: tests/test_p2p.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -pthread -o $@ $^

clean:
	rm -f $(OBJ) simplecipher tests/test_p2p

.PHONY: test clean
