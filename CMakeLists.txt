cmake_minimum_required(VERSION 3.20)
project(simplecipher C)

# C23 standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---- Security-hardened release flags ----
#
# Compiler hardening:
#   -Os                        optimize for size (smaller attack surface)
#   -flto                      link-time optimization (whole-program analysis)
#   -ffunction-sections/data   enable linker dead-code removal
#   -fmerge-all-constants      merge identical const data
#   -fstack-protector-strong   stack canaries on functions with arrays/locals
#   -fstack-clash-protection   guard pages to detect stack clash attacks
#   -fcf-protection            control-flow integrity (x86_64: CET IBT/SHSTK)
#   -ftrivial-auto-var-init=zero  zero-initialize all auto variables
#   -D_FORTIFY_SOURCE=3        runtime buffer overflow detection (strongest level)
#   -DNDEBUG                   disable assert()
#   -fno-delete-null-pointer-checks  don't optimize away null checks
#   -fno-strict-overflow       don't optimize based on signed overflow UB
#   -fno-strict-aliasing       don't optimize based on strict aliasing rules
#   -Wall -Wextra -Werror=implicit -Werror=return-type -Werror=unused-result
#
# Strip metadata (not security features):
#   -fno-unwind-tables -fno-asynchronous-unwind-tables  drop .eh_frame
#   -fno-ident                 strip compiler version string (Linux)
#
set(COMMON_C_FLAGS "\
-Os -flto \
-ffunction-sections -fdata-sections -fmerge-all-constants \
-fstack-protector-strong \
-ftrivial-auto-var-init=zero \
-fvisibility=hidden \
-DNDEBUG -DCIPHER_HARDEN \
-fno-delete-null-pointer-checks \
-fno-strict-overflow \
-fno-strict-aliasing \
-fstrict-flex-arrays=3 \
-fno-unwind-tables -fno-asynchronous-unwind-tables \
-Wall -Wextra -Wformat=2 -Wconversion -Wimplicit-fallthrough \
-Wbidi-chars=any \
-Werror=implicit -Werror=return-type -Werror=unused-result \
-Werror=format-security -Werror=incompatible-pointer-types -Werror=int-conversion \
")

# Platform-specific compiler hardening (not universally supported)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # -fstack-clash-protection   guard pages to detect stack clash attacks
    # -D_FORTIFY_SOURCE=3        runtime buffer overflow detection (strongest)
    string(APPEND COMMON_C_FLAGS " -fstack-clash-protection -D_FORTIFY_SOURCE=3")
endif()

# Architecture-specific hardening + tuning
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    # CET: Intel Control-flow Enforcement Technology (IBT + Shadow Stack)
    string(APPEND COMMON_C_FLAGS " -march=x86-64-v3 -fcf-protection=full")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    # BTI: Branch Target Identification (aarch64 CFI)
    string(APPEND COMMON_C_FLAGS " -march=armv8-a -mbranch-protection=standard")
endif()

# Platform-specific linker hardening
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # ELF linker hardening:
    #   --gc-sections       remove unreferenced code/data
    #   -z,relro            read-only relocations (GOT hardening)
    #   -z,now              immediate binding (full RELRO)
    #   -z,noexecstack      non-executable stack
    #   --build-id=none     strip build-id metadata
    set(CMAKE_C_FLAGS_RELEASE "${COMMON_C_FLAGS} -fno-ident")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-flto -Wl,--gc-sections -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,nodlopen -Wl,--build-id=none")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # PE linker hardening:
    #   --gc-sections       remove unreferenced code/data
    #   --dynamicbase       ASLR
    #   --high-entropy-va   64-bit ASLR with high entropy
    #   --nxcompat          DEP (data execution prevention)
    set(CMAKE_C_FLAGS_RELEASE "${COMMON_C_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-flto -Wl,--gc-sections -Wl,--dynamicbase -Wl,--high-entropy-va -Wl,--nxcompat")
else()
    set(CMAKE_C_FLAGS_RELEASE "${COMMON_C_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-flto -Wl,--gc-sections")
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ---- source files ----
set(CORE_SRC
    src/platform.c
    src/crypto.c
    src/protocol.c
    src/ratchet.c
    src/network.c
    src/tui.c
    src/cli.c
    lib/monocypher.c
)

if(WIN32)
    set(PLATFORM_SRC src/tui_win.c src/cli_win.c)
else()
    set(PLATFORM_SRC src/tui_posix.c src/cli_posix.c)
endif()

# Suppress -Wconversion for vendored Monocypher (upstream code, do not modify).
set_source_files_properties(lib/monocypher.c PROPERTIES COMPILE_FLAGS -Wno-conversion)

add_executable(simplecipher src/main.c ${CORE_SRC} ${PLATFORM_SRC})
target_include_directories(simplecipher PRIVATE src lib)

# Windows requires Winsock2 and BCrypt for networking and CSPRNG
if(WIN32)
    target_link_libraries(simplecipher ws2_32 bcrypt iphlpapi)
endif()

# P2P integration test (native builds only, needs pthreads)
if(NOT CMAKE_CROSSCOMPILING)
    add_executable(test_p2p tests/test_p2p.c ${CORE_SRC} ${PLATFORM_SRC})
    target_include_directories(test_p2p PRIVATE src lib)
    target_link_libraries(test_p2p pthread)
    add_test(NAME p2p COMMAND test_p2p)
    enable_testing()
endif()

# Fuzz targets (requires clang -fsanitize=fuzzer; enable with -DFUZZ=ON)
option(FUZZ "Build libFuzzer fuzz targets" OFF)
if(FUZZ)
    foreach(target fuzz_frame_open fuzz_sanitize fuzz_validate_port)
        add_executable(${target} tests/${target}.c ${CORE_SRC} ${PLATFORM_SRC})
        target_include_directories(${target} PRIVATE src lib)
        target_compile_options(${target} PRIVATE
            -g -O1 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE
            -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()
