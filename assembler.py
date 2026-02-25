#!/usr/bin/env python3
"""
Keystone x86 assembler — reads an .asm file, assembles it, outputs hex.

Usage:
    python3 assembler.py [file.asm]

If no file is given, defaults to revshell.asm in the same directory.

Output formats printed:
    - Raw hex string  (paste into Wireshark / CyberChef)
    - Python bytes    (paste directly into an exploit script)
    - C byte array    (paste into a C/C++ exploit)
    - Byte count + any null bytes flagged (bad character check)
"""

import sys
import os
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KsError


def strip_comments(asm: str) -> str:
    """Remove ; comments so Keystone doesn't choke on them."""
    return "\n".join(line.split(";")[0] for line in asm.splitlines())


def assemble(asm_path: str) -> bytes:
    with open(asm_path, "r") as f:
        raw = f.read()

    cleaned = strip_comments(raw)

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    try:
        encoding, count = ks.asm(cleaned)
    except KsError as e:
        print(f"[!] Assembly error: {e}")
        sys.exit(1)

    print(f"[+] Assembled {count} instructions, {len(encoding)} bytes\n")
    return bytes(encoding)


def print_formats(shellcode: bytes) -> None:
    # --- Raw hex string ---
    hex_str = shellcode.hex()
    print("[ Raw hex ]")
    print(hex_str)
    print()

    # --- Python bytes literal ---
    py_bytes = "shellcode = b\"" + "".join(f"\\x{b:02x}" for b in shellcode) + "\""
    print("[ Python bytes ]")
    print(py_bytes)
    print()

    # --- C byte array ---
    c_array = "unsigned char shellcode[] = {\n    "
    chunks = [f"0x{b:02x}" for b in shellcode]
    # 12 bytes per line
    lines = [", ".join(chunks[i:i+12]) for i in range(0, len(chunks), 12)]
    c_array += ",\n    ".join(lines)
    c_array += "\n};"
    print("[ C array ]")
    print(c_array)
    print()

    # --- Bad character check ---
    bad = [f"\\x{b:02x}" for b in shellcode if b == 0x00]
    if bad:
        print(f"[!] NULL bytes found ({len(bad)}): {', '.join(bad)}")
    else:
        print("[+] No null bytes detected")


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))

    if len(sys.argv) > 1:
        asm_file = sys.argv[1]
    else:
        asm_file = os.path.join(script_dir, "revshell.asm")

    if not os.path.isfile(asm_file):
        print(f"[!] File not found: {asm_file}")
        sys.exit(1)

    print(f"[*] Assembling: {asm_file}\n")
    shellcode = assemble(asm_file)
    print_formats(shellcode)
