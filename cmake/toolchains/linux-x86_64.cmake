# Cross-compilation toolchain: Linux x86_64 (musl, static, hardened)
#
# Uses a crosstool-NG built GCC with musl libc and the mold linker.
# Expects the toolchain extracted at /opt/x-tools/x86_64-unknown-linux-musl.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(TOOLCHAIN_PREFIX x86_64-unknown-linux-musl)
set(TOOLCHAIN_DIR /opt/x-tools/${TOOLCHAIN_PREFIX})

set(CMAKE_C_COMPILER ${TOOLCHAIN_DIR}/bin/${TOOLCHAIN_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_DIR}/bin/${TOOLCHAIN_PREFIX}-g++)
set(CMAKE_AR ${TOOLCHAIN_DIR}/bin/${TOOLCHAIN_PREFIX}-ar)
set(CMAKE_RANLIB ${TOOLCHAIN_DIR}/bin/${TOOLCHAIN_PREFIX}-ranlib)
set(CMAKE_LINKER ${TOOLCHAIN_DIR}/x86_64-unknown-linux-musl/bin/mold)

set(CMAKE_SYSROOT ${TOOLCHAIN_DIR}/${TOOLCHAIN_PREFIX}/sysroot)
set(CMAKE_FIND_ROOT_PATH ${CMAKE_SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# -fuse-ld=mold   mold linker
# -static-pie      fully static PIE binary (ASLR)
# -s               strip all symbols
set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=mold -static-pie -s")
