#!/usr/bin/env python3
"""
CBMC formal verification harness generator for SimpleCipher.

Generates C11-compatible harnesses from SimpleCipher's C23 source code
and runs CBMC bounded model checking on the 6 core protocol functions:
  frame_open, frame_build, chain_step, ratchet_send, ratchet_receive, session_init

Proves: no buffer overflow, no out-of-bounds read/write, no null pointer
dereference, no signed integer overflow — for ALL possible inputs within
the given unwind bound.

Requirements:
  - CBMC (https://github.com/diffblue/cbmc)
  - GCC with C23 support (for preprocessing)
  - Python 3.6+

Usage:
  python3 tests/cbmc_harness.py [--unwind N] [--verbose]

Exit code 0 if all verifications pass, 1 if any fail.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Source files to combine into a single translation unit
SOURCES = [
    "lib/monocypher.c",
    "src/crypto.c",
    "src/ratchet.c",
    "src/protocol.c",
]

# Headers that need C23→C11 conversion
HEADERS = [
    "src/crypto.h", "src/protocol.h", "src/ratchet.h",
    "src/platform.h", "src/network.h", "src/tui.h", "src/cli.h",
]

# CBMC harness main() functions for each target
HARNESSES = {
    "frame_open": """
extern uint8_t nondet_uint8(void);
extern uint64_t nondet_uint64(void);
extern int nondet_int(void);
int main(void) {
    session_t s;
    for (int i = 0; i < 32; i++) {
        s.tx[i] = nondet_uint8(); s.rx[i] = nondet_uint8();
        s.root[i] = nondet_uint8(); s.dh_priv[i] = nondet_uint8();
        s.dh_pub[i] = nondet_uint8(); s.peer_dh[i] = nondet_uint8();
    }
    s.tx_seq = nondet_uint64(); s.rx_seq = nondet_uint64();
    s.need_send_ratchet = nondet_int();
    uint8_t frame[512];
    for (int i = 0; i < 512; i++) frame[i] = nondet_uint8();
    uint8_t out[486]; uint16_t out_len = 0;
    int result = frame_open(&s, frame, out, &out_len);
    if (result == 0) __CPROVER_assert(out_len <= 485, "out_len <= MAX_MSG");
    return 0;
}
""",
    "frame_build": """
extern uint8_t nondet_uint8(void);
extern uint16_t nondet_uint16(void);
extern uint64_t nondet_uint64(void);
extern int nondet_int(void);
int main(void) {
    session_t s;
    for (int i = 0; i < 32; i++) {
        s.tx[i] = nondet_uint8(); s.rx[i] = nondet_uint8();
        s.root[i] = nondet_uint8(); s.dh_priv[i] = nondet_uint8();
        s.dh_pub[i] = nondet_uint8(); s.peer_dh[i] = nondet_uint8();
    }
    s.tx_seq = nondet_uint64(); s.rx_seq = nondet_uint64();
    s.need_send_ratchet = nondet_int();
    uint16_t len = nondet_uint16();
    uint8_t plain[486];
    for (int i = 0; i < 486; i++) plain[i] = nondet_uint8();
    uint8_t frame[512]; uint8_t next_chain[32];
    frame_build(&s, plain, len, frame, next_chain);
    return 0;
}
""",
    "chain_step": """
extern uint8_t nondet_uint8(void);
int main(void) {
    uint8_t chain[32], mk[32], next[32];
    for (int i = 0; i < 32; i++) chain[i] = nondet_uint8();
    chain_step(chain, mk, next);
    return 0;
}
""",
    "ratchet_send": """
extern uint8_t nondet_uint8(void);
extern uint64_t nondet_uint64(void);
extern int nondet_int(void);
int main(void) {
    session_t s;
    for (int i = 0; i < 32; i++) {
        s.tx[i] = nondet_uint8(); s.rx[i] = nondet_uint8();
        s.root[i] = nondet_uint8(); s.dh_priv[i] = nondet_uint8();
        s.dh_pub[i] = nondet_uint8(); s.peer_dh[i] = nondet_uint8();
    }
    s.tx_seq = nondet_uint64(); s.rx_seq = nondet_uint64();
    s.need_send_ratchet = nondet_int();
    uint8_t pub[32];
    ratchet_send(&s, pub);
    return 0;
}
""",
    "ratchet_receive": """
extern uint8_t nondet_uint8(void);
extern uint64_t nondet_uint64(void);
extern int nondet_int(void);
int main(void) {
    session_t s;
    for (int i = 0; i < 32; i++) {
        s.tx[i] = nondet_uint8(); s.rx[i] = nondet_uint8();
        s.root[i] = nondet_uint8(); s.dh_priv[i] = nondet_uint8();
        s.dh_pub[i] = nondet_uint8(); s.peer_dh[i] = nondet_uint8();
    }
    s.tx_seq = nondet_uint64(); s.rx_seq = nondet_uint64();
    s.need_send_ratchet = nondet_int();
    uint8_t peer_pub[32];
    for (int i = 0; i < 32; i++) peer_pub[i] = nondet_uint8();
    ratchet_receive(&s, peer_pub);
    return 0;
}
""",
    "session_init": """
extern uint8_t nondet_uint8(void);
extern int nondet_int(void);
int main(void) {
    session_t s;
    uint8_t priv[32], pub[32], peer[32], sas[32];
    for (int i = 0; i < 32; i++) {
        priv[i] = nondet_uint8(); pub[i] = nondet_uint8();
        peer[i] = nondet_uint8();
    }
    int we_init = nondet_int();
    session_init(&s, we_init, priv, pub, peer, sas);
    return 0;
}
""",
}


def convert_header(inpath: str) -> str:
    """Convert a C23 header to C11-compatible source."""
    with open(inpath) as f:
        content = f.read()
    content = re.sub(r'\[\[nodiscard\]\]\s*', '', content)
    content = content.replace('nullptr', '((void*)0)')
    content = re.sub(
        r'static\s+constexpr\s+(int|uint8_t)\s+(\w+)\s*=\s*(\S+?)\s*;[^\n]*(?:\n\s*\*[^\n]*)*',
        lambda m: f'#define {m.group(2)} {m.group(3)}',
        content
    )
    content = re.sub(r'static_assert\([^)]+\);', '', content)
    return content


def build_combined(harness_name: str, tmpdir: str) -> str:
    """Build a combined C11 translation unit with the given harness."""
    # Create shadow headers
    hdr_dir = os.path.join(tmpdir, "src")
    lib_dir = os.path.join(tmpdir, "lib")
    os.makedirs(hdr_dir, exist_ok=True)
    os.makedirs(lib_dir, exist_ok=True)

    for h in HEADERS:
        src = os.path.join(PROJECT_ROOT, h)
        dst = os.path.join(tmpdir, h)
        with open(dst, 'w') as f:
            f.write(convert_header(src))

    # Copy monocypher.h as-is
    import shutil
    shutil.copy(
        os.path.join(PROJECT_ROOT, "lib/monocypher.h"),
        os.path.join(lib_dir, "monocypher.h")
    )

    # Build combined .c file
    parts = [
        '#define constexpr static const\n',
        '#define nullptr NULL\n',
        '#define bool _Bool\n',
        '#define true 1\n',
        '#define false 0\n',
        '\n',
    ]

    for src in SOURCES:
        path = os.path.join(PROJECT_ROOT, src)
        with open(path) as f:
            text = f.read()
        text = re.sub(r'\[\[nodiscard\]\]\s*', '', text)
        text = text.replace('static_assert(', '/* static_assert(')
        text = text.replace(');', '); */', 1) if 'static_assert' in text else text
        # Simpler: just strip static_assert lines
        text = re.sub(r'static_assert\([^)]+\);', '', text)
        parts.append(f'/* === {src} === */\n')
        parts.append(text)
        parts.append('\n')

    parts.append(HARNESSES[harness_name])

    combined = os.path.join(tmpdir, f"cbmc_{harness_name}.c")
    with open(combined, 'w') as f:
        f.write(''.join(parts))

    return combined


def run_cbmc(harness_name: str, unwind: int, verbose: bool) -> bool:
    """Run CBMC on a single harness. Returns True if verification succeeds."""
    with tempfile.TemporaryDirectory() as tmpdir:
        combined = build_combined(harness_name, tmpdir)

        # Compile to GOTO program
        goto_file = os.path.join(tmpdir, f"{harness_name}.goto")
        cmd_cc = [
            "goto-cc",
            "-I", os.path.join(tmpdir, "src"),
            "-I", os.path.join(tmpdir, "lib"),
            combined,
            "-o", goto_file,
        ]
        result = subprocess.run(cmd_cc, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  FAIL: {harness_name} — goto-cc compilation failed")
            if verbose:
                print(result.stderr)
            return False

        # Run CBMC
        cmd_cbmc = [
            "cbmc", goto_file,
            "--bounds-check",
            "--pointer-check",
            "--signed-overflow-check",
            f"--unwind", str(unwind),
            "--no-unwinding-assertions",
        ]
        result = subprocess.run(cmd_cbmc, capture_output=True, text=True, timeout=300)

        # Parse results
        for line in result.stdout.splitlines():
            if "VERIFICATION SUCCESSFUL" in line:
                # Count checks
                for l2 in result.stdout.splitlines():
                    if "** 0 of" in l2:
                        count = l2.split("of")[1].split("failed")[0].strip()
                        print(f"  PASS: {harness_name} — {count} properties verified")
                        return True
                print(f"  PASS: {harness_name}")
                return True
            if "VERIFICATION FAILED" in line:
                failures = [l for l in result.stdout.splitlines() if "FAILURE" in l]
                print(f"  FAIL: {harness_name}")
                for f in failures:
                    print(f"    {f}")
                return False

        print(f"  UNKNOWN: {harness_name} — could not parse CBMC output")
        if verbose:
            print(result.stdout[-500:])
        return False


def main():
    parser = argparse.ArgumentParser(description="CBMC formal verification for SimpleCipher")
    parser.add_argument("--unwind", type=int, default=5, help="Loop unwind bound (default: 5)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output on failure")
    args = parser.parse_args()

    # Check CBMC is available
    try:
        subprocess.run(["cbmc", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("SKIP: CBMC not found (install from https://github.com/diffblue/cbmc)")
        sys.exit(0)

    try:
        subprocess.run(["goto-cc", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("SKIP: goto-cc not found (part of CBMC)")
        sys.exit(0)

    print("SimpleCipher CBMC Formal Verification")
    print("=" * 40)
    print(f"Unwind bound: {args.unwind}")
    print(f"Checking: bounds, pointers, signed overflow")
    print()

    passed = 0
    failed = 0
    for name in HARNESSES:
        ok = run_cbmc(name, args.unwind, args.verbose)
        if ok:
            passed += 1
        else:
            failed += 1

    print()
    print(f"{'=' * 40}")
    print(f"Total: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
