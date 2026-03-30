CC      ?= gcc

# ---- Compiler capability detection ----------------------------------------
# Probe whether $(CC) accepts a flag.  Returns the flag if supported, empty
# string otherwise.  Runs once per flag during Makefile parsing.
cc_ok = $(shell echo 'int main(){return 0;}' | $(CC) $(1) -x c - -o /dev/null 2>/dev/null && echo $(1))

# Detect C23 vs C2x support (Apple Clang, older Clang need -std=c2x)
STD_FLAG := $(or $(call cc_ok,-std=c23),-std=c2x)

# ---- Security-critical flags — always applied, cannot be overridden --------
# CIPHER_HARDEN enables mlockall, core dump suppression, ptrace blocking,
# and seccomp/Capsicum/pledge sandboxing.
SECURITY_CFLAGS = -DCIPHER_HARDEN -DNDEBUG \
                  -fstack-protector-strong \
                  -fvisibility=hidden \
                  -fno-strict-aliasing \
                  $(call cc_ok,-ftrivial-auto-var-init=zero) \
                  $(call cc_ok,-fno-delete-null-pointer-checks) \
                  $(call cc_ok,-fno-strict-overflow) \
                  $(call cc_ok,-fstrict-flex-arrays=3)

# ---- User-overridable flags (optimization, warnings, includes) -------------
CFLAGS  ?= -Os $(STD_FLAG) -Wall -Wextra -Wformat=2 -Wconversion -Wimplicit-fallthrough \
           $(call cc_ok,-Wbidi-chars=any) \
           -Werror=format-security -Werror=incompatible-pointer-types -Werror=int-conversion \
           -Werror=implicit -Werror=return-type -Werror=unused-result \
           -Isrc -Ilib \
           -flto -ffunction-sections -fdata-sections -fmerge-all-constants

# Combined: security flags are prepended and cannot be removed by overriding CFLAGS.
ALL_CFLAGS = $(SECURITY_CFLAGS) $(CFLAGS)

LIBS    ?= -lm

# Core sources (platform-independent + small inline #ifdefs)
CORE_SRC = src/platform.c src/crypto.c src/protocol.c src/ratchet.c src/network.c \
           src/nb_io.c src/tui.c src/cli.c src/args.c src/verify.c lib/monocypher.c

# Platform-specific event loops, hardening, and linker flags
UNAME := $(shell uname -s)
ifeq ($(UNAME),Linux)
  PLAT_SRC = src/tui_posix.c src/cli_posix.c
  CFLAGS  += $(call cc_ok,-fstack-clash-protection) $(call cc_ok,-D_FORTIFY_SOURCE=3)
  CFLAGS  += $(call cc_ok,-fcf-protection=full)
  LDFLAGS ?= -flto -Wl,--gc-sections -s
  LDFLAGS += -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,nodlopen
else ifeq ($(UNAME),Darwin)
  PLAT_SRC = src/tui_posix.c src/cli_posix.c
  LDFLAGS ?= -flto -Wl,-dead_strip -Wl,-x
else ifeq ($(UNAME),OpenBSD)
  PLAT_SRC = src/tui_posix.c src/cli_posix.c
  LDFLAGS ?= -flto -Wl,--gc-sections -s
else ifeq ($(UNAME),FreeBSD)
  PLAT_SRC = src/tui_posix.c src/cli_posix.c
  LDFLAGS ?= -flto -Wl,--gc-sections -s
else
  PLAT_SRC = src/tui_win.c src/cli_win.c
  LDFLAGS ?= -flto -Wl,--gc-sections -s
  LDFLAGS += -lws2_32 -lbcrypt -liphlpapi -ladvapi32
endif

SRC = src/main.c $(CORE_SRC) $(PLAT_SRC)
OBJ = $(SRC:.c=.o)

simplecipher: $(OBJ)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

# Vendored Monocypher: -Wno-conversion (upstream code, do not modify).
# -fno-lto is security-critical: keeps crypto_wipe() opaque to LTO so the
# linker cannot see through the volatile writes and eliminate wipe calls.
lib/monocypher.o: lib/monocypher.c
	$(CC) $(ALL_CFLAGS) -Wno-conversion -fno-lto -c -o $@ $<

test: tests/test_p2p
	./tests/test_p2p

test-socks5: tests/test_socks5_proxy
	./tests/test_socks5_proxy

LIB_OBJ = $(filter-out src/main.o,$(OBJ))
tests/test_p2p: tests/test_p2p.c $(LIB_OBJ)
	$(CC) $(ALL_CFLAGS) -pthread -o $@ $^ -lm

tests/test_socks5_proxy: tests/test_socks5_proxy.c $(LIB_OBJ)
	$(CC) $(ALL_CFLAGS) -pthread -o $@ $^ -lm

test-all: test test-socks5 simplecipher
	bash tests/test_cli_flags.sh ./simplecipher

clean:
	rm -f $(OBJ) simplecipher tests/test_p2p tests/test_socks5_proxy

.PHONY: test test-all clean
