#!/usr/bin/env bash
# Build-level tests — run after toolchains are available but before the main build.
# Verifies CMake configuration and compiler requirements.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

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
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
