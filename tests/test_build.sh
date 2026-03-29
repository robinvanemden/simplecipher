#!/usr/bin/env bash
# Build-level tests — run after toolchains are available but before the main build.
# Verifies CMake configuration and compiler requirements.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
# Reject paths with shell metacharacters to prevent eval injection.
case "$PROJECT_DIR" in *[\'\"\`\$\;\&\|\!\(\)\{\}\[\]]*) echo "ERROR: project path contains shell metacharacters" >&2; exit 1;; esac

PASS=0
FAIL=0

check() {
    local desc="$1"
    shift
    if eval "$@" >/dev/null 2>&1; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Build: CMake configure ==="

BUILD_LINUX="/tmp/test_build_linux_$$"
BUILD_LINUX_ARM="/tmp/test_build_linux_arm_$$"
BUILD_WIN="/tmp/test_build_win_$$"
BUILD_WIN_ARM="/tmp/test_build_win_arm_$$"
cleanup() { rm -rf "$BUILD_LINUX" "$BUILD_LINUX_ARM" "$BUILD_WIN" "$BUILD_WIN_ARM"; }
trap cleanup EXIT

# Linux presets configure successfully
check "linux-x86_64 preset configures" \
    "cmake --preset linux-x86_64 -B '$BUILD_LINUX' -S '$PROJECT_DIR' 2>&1"

check "linux-aarch64 preset configures" \
    "cmake --preset linux-aarch64 -B '$BUILD_LINUX_ARM' -S '$PROJECT_DIR' 2>&1"

# Windows presets configure successfully
check "win-x86_64 preset configures" \
    "cmake --preset win-x86_64 -B '$BUILD_WIN' -S '$PROJECT_DIR' 2>&1"

check "win-aarch64 preset configures" \
    "cmake --preset win-aarch64 -B '$BUILD_WIN_ARM' -S '$PROJECT_DIR' 2>&1"

echo ""
echo "=== Build: C23 requirement ==="

# C23 is enforced — check that the compiler flags contain a C23 standard flag
# GCC 14+ uses -std=c23/gnu23, GCC 13 uses -std=c2x/gnu2x (both mean C23)
C23_PAT='std=gnu23\|std=c23\|std=gnu2x\|std=c2x'
check "linux x86_64 build uses C23 flag" \
    "grep -q '$C23_PAT' '$BUILD_LINUX/CMakeFiles/simplecipher.dir/flags.make'"
check "linux aarch64 build uses C23 flag" \
    "grep -q '$C23_PAT' '$BUILD_LINUX_ARM/CMakeFiles/simplecipher.dir/flags.make'"
check "windows x86_64 build uses C23 flag" \
    "grep -q '$C23_PAT' '$BUILD_WIN/CMakeFiles/simplecipher.dir/flags.make'"
check "windows aarch64 build uses C23 flag" \
    "grep -q '$C23_PAT' '$BUILD_WIN_ARM/CMakeFiles/simplecipher.dir/flags.make'"

echo ""
echo "=== Build: CIPHER_HARDEN requirement ==="

# All builds must define CIPHER_HARDEN for runtime hardening (mlockall,
# RLIMIT_CORE, PR_SET_DUMPABLE, seccomp).  The Android CMakeLists.txt
# was missing this — a test catches the regression.
check "linux x86_64 build uses CIPHER_HARDEN" \
    "grep -q 'CIPHER_HARDEN' '$BUILD_LINUX/CMakeFiles/simplecipher.dir/flags.make'"
check "linux aarch64 build uses CIPHER_HARDEN" \
    "grep -q 'CIPHER_HARDEN' '$BUILD_LINUX_ARM/CMakeFiles/simplecipher.dir/flags.make'"
check "Android build uses CIPHER_HARDEN" \
    "grep -q 'CIPHER_HARDEN' '$PROJECT_DIR/android/app/src/main/c/CMakeLists.txt'"
check "Makefile has non-overridable SECURITY_CFLAGS with CIPHER_HARDEN" \
    "grep 'SECURITY_CFLAGS' '$PROJECT_DIR/Makefile' | grep -q 'CIPHER_HARDEN'"

echo ""
echo "=== Build: safety checks ==="

# listen_socket_cb must use poll() on POSIX (not select/FD_SET which
# overflows when fd >= FD_SETSIZE).  The Windows path retains select()
# which is safe (Windows fd_set is a handle array, not a bitmap).
check "network.c uses poll() for listen_socket_cb on POSIX (no FD_SET overflow)" \
    "grep -q 'poll(&pfd' '$PROJECT_DIR/src/network.c'"

# Verify CFLAGS override can't remove hardening: run dry-run from project dir
MAKE_CHECK=$(make -n -B -C "$PROJECT_DIR" CFLAGS="-O0" simplecipher 2>&1 || true)
check "make CFLAGS override cannot drop CIPHER_HARDEN" \
    "echo \"$MAKE_CHECK\" | grep -q CIPHER_HARDEN"

echo ""
echo "=== Vendored library integrity ==="

# Verify monocypher.c and monocypher.h have not been accidentally modified.
# These checksums correspond to the vendored Monocypher version.  Update them
# only when intentionally upgrading the library.
MONO_C_HASH="$(sha256sum "$PROJECT_DIR/lib/monocypher.c" 2>/dev/null | cut -d' ' -f1)"
MONO_H_HASH="$(sha256sum "$PROJECT_DIR/lib/monocypher.h" 2>/dev/null | cut -d' ' -f1)"

check "lib/monocypher.c exists" "test -f '$PROJECT_DIR/lib/monocypher.c'"
check "lib/monocypher.h exists" "test -f '$PROJECT_DIR/lib/monocypher.h'"

# Hardcoded hashes of the vendored Monocypher files.  If these fail after
# a legitimate upgrade, regenerate with: sha256sum lib/monocypher.c lib/monocypher.h
EXPECTED_C="02174117935699d418443c75a558a287deb06ef8cf7c1adced61d9047d2f323d"
EXPECTED_H="fcaf6ed771358bb4f40fba016f6518ae86ec02b1b877d2cc35ad92d3a26fd7b3"
check "monocypher.c integrity (sha256)" \
    "test '$MONO_C_HASH' = '$EXPECTED_C'"
check "monocypher.h integrity (sha256)" \
    "test '$MONO_H_HASH' = '$EXPECTED_H'"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
