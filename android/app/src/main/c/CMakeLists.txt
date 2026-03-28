cmake_minimum_required(VERSION 3.20)
project(simplecipher C)

# Project root is 5 levels up from this CMakeLists.txt:
# android/app/src/main/c/ → project root
set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../..")

add_library(simplecipher SHARED
    jni_bridge.c
    "${PROJECT_ROOT}/src/platform.c"
    "${PROJECT_ROOT}/src/crypto.c"
    "${PROJECT_ROOT}/src/protocol.c"
    "${PROJECT_ROOT}/src/ratchet.c"
    "${PROJECT_ROOT}/src/network.c"
    "${PROJECT_ROOT}/src/tui.c"
    "${PROJECT_ROOT}/src/tui_posix.c"
    "${PROJECT_ROOT}/src/cli.c"
    "${PROJECT_ROOT}/src/cli_posix.c"
    "${PROJECT_ROOT}/lib/monocypher.c"
)

target_include_directories(simplecipher PRIVATE
    "${PROJECT_ROOT}/src"
    "${PROJECT_ROOT}/lib"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

# Suppress -Wconversion for vendored Monocypher (upstream code, do not modify)
set_source_files_properties("${PROJECT_ROOT}/lib/monocypher.c" PROPERTIES COMPILE_FLAGS -Wno-conversion)

# Security-hardened compile options for Android NDK (Clang)
target_compile_options(simplecipher PRIVATE
    -std=c23
    -Os -ffunction-sections -fdata-sections -fmerge-all-constants -DNDEBUG
    -DCIPHER_HARDEN
    -D_FORTIFY_SOURCE=3
    -fstack-protector-strong
    -ftrivial-auto-var-init=zero
    -fno-delete-null-pointer-checks
    -fno-strict-overflow
    -fno-strict-aliasing
    # Hide all symbols by default; only JNI exports are visible
    -fvisibility=hidden
    # LTO for whole-program optimization
    -flto
    # Note: -fsanitize=cfi was removed — CFI + LTO + version script caused
    # the linker to strip all internal functions, producing a ~6KB .so that
    # crashed on System.loadLibrary.  CFI instrumentation changes the call
    # graph in ways that make LTO think internal code is unreachable.
    # The remaining hardening (RELRO, stack canary, BTI, hidden visibility,
    # version script) still provides strong protection.
    -Wall -Wextra -Wformat=2 -Wconversion -Wimplicit-fallthrough
    -Werror=implicit -Werror=return-type -Werror=unused-result
    -Werror=format-security -Werror=incompatible-pointer-types -Werror=int-conversion
)

# ARM64-only: Pointer Authentication + Branch Target Identification
# Hardware-backed on ARMv8.3+, harmless NOPs on older ARMv8 chips.
# Not available on 32-bit ARM (armeabi-v7a).
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_compile_options(simplecipher PRIVATE -mbranch-protection=standard)
endif()

# Linker hardening: full RELRO, no lazy binding, strip symbols and unused sections
target_link_options(simplecipher PRIVATE
    -Wl,-z,relro,-z,now
    -Wl,--as-needed
    -Wl,-s
    # Only export JNI entry points — everything else is hidden.
    # Note: --gc-sections is intentionally omitted here because combined
    # with the version script + LTO + CFI, it strips internal functions
    # that are called indirectly through the JNI bridge, producing a
    # ~5KB .so that crashes on load.  The version script + -fvisibility=hidden
    # already ensures no internal symbols are exported.
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/jni_exports.map
    -flto
)

target_link_libraries(simplecipher log)
