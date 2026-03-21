# Cross-compilation toolchain: Windows aarch64 (llvm-mingw, static, hardened)
#
# Uses llvm-mingw (Clang-based) with UCRT.
# Expects the toolchain extracted at /opt/llvm-mingw-*.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(TOOLCHAIN_DIR /opt/llvm-mingw-20260311-ucrt-ubuntu-22.04-x86_64)
set(TOOLCHAIN_PREFIX aarch64-w64-mingw32)

set(CMAKE_C_COMPILER ${TOOLCHAIN_DIR}/bin/${TOOLCHAIN_PREFIX}-clang)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_DIR}/bin/${TOOLCHAIN_PREFIX}-clang++)
set(CMAKE_RC_COMPILER ${TOOLCHAIN_DIR}/bin/${TOOLCHAIN_PREFIX}-windres)
set(CMAKE_AR ${TOOLCHAIN_DIR}/bin/${TOOLCHAIN_PREFIX}-ar)
set(CMAKE_RANLIB ${TOOLCHAIN_DIR}/bin/${TOOLCHAIN_PREFIX}-ranlib)

set(CMAKE_FIND_ROOT_PATH ${TOOLCHAIN_DIR}/${TOOLCHAIN_PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# -static   fully static (no UCRT/mingw DLL dependency)
# -s        strip all symbols
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static -s")
