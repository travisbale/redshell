#!/usr/bin/env python3

import sys
import os
import re
import argparse
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KsError
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def strip_comments(asm: str) -> str:
    """Remove ; comments so Keystone doesn't choke on them."""
    return "\n".join(line.split(";")[0] for line in asm.splitlines())


def parse_badchars(raw: str) -> set:
    """Parse a msfvenom-style bad character string into a set of ints.

    Accepts formats like: "\\x00\\x0a\\x0d" or "00 0a 0d" or "00,0a,0d"
    """
    tokens = re.findall(r"[0-9a-fA-F]{2}", raw)
    return set(int(t, 16) for t in tokens)


def ror32(val: int, count: int) -> int:
    return ((val >> count) | (val << (32 - count))) & 0xFFFFFFFF


def ror13_hash(name: str) -> int:
    """Compute the ROR-13 hash of a function name string (no null terminator)."""
    h = 0
    for i, c in enumerate(name):
        h = (h + ord(c)) & 0xFFFFFFFF
        if i < len(name) - 1:
            h = ror32(h, 13)
    return h


def ip_to_dword(ip: str) -> str:
    """Convert a dotted-decimal IP to a little-endian dword hex string.

    e.g. "192.168.119.120" -> "0x7877a8c0"
    """
    octets = list(map(int, ip.split(".")))
    if len(octets) != 4 or not all(0 <= o <= 255 for o in octets):
        print(f"[!] Invalid IP address: {ip}")
        sys.exit(1)
    dword = (octets[3] << 24) | (octets[2] << 16) | (octets[1] << 8) | octets[0]
    return f"0x{dword:08x}"


def port_to_word(port: int) -> str:
    """Convert a port number to its network byte order (big-endian) word hex string.

    e.g. 443 (0x01bb) -> "0xbb01"  (bytes swapped for mov ax immediate)
    """
    if not (1 <= port <= 65535):
        print(f"[!] Invalid port: {port}")
        sys.exit(1)
    swapped = ((port & 0xFF) << 8) | (port >> 8)
    return f"0x{swapped:04x}"


def apply_substitutions(asm_text: str, ip: str = None, port: int = None) -> str:
    """Replace all placeholders in asm source before assembling.

    Handles:
      HASH_<FuncName>  ->  ROR-13 hash of FuncName as a hex immediate
      LHOST_DWORD      ->  little-endian dword encoding of -i IP
      LPORT_WORD       ->  network byte order word encoding of -p port
    """
    # HASH_<FuncName> substitution
    for match in re.finditer(r"HASH_([A-Za-z0-9]+)", asm_text):
        func_name = match.group(1)
        h = ror13_hash(func_name)
        asm_text = asm_text.replace(match.group(0), f"{h:#010x}")

    if "LHOST_DWORD" in asm_text:
        if ip is None:
            print("[!] LHOST_DWORD found in asm but no -i <ip> provided.")
            sys.exit(1)
        asm_text = asm_text.replace("LHOST_DWORD", ip_to_dword(ip))

    if "LPORT_WORD" in asm_text:
        if port is None:
            print("[!] LPORT_WORD found in asm but no -p <port> provided.")
            sys.exit(1)
        asm_text = asm_text.replace("LPORT_WORD", port_to_word(port))

    return asm_text


def assemble(asm_path: str, ip: str = None, port: int = None, debug: bool = False) -> bytes:
    with open(asm_path, "r") as f:
        raw = f.read()

    if debug:
        raw = "int3\n" + raw

    raw = apply_substitutions(raw, ip, port)
    cleaned = strip_comments(raw)

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    try:
        encoding, count = ks.asm(cleaned)
    except KsError as e:
        print(f"[!] Assembly error: {e}")
        sys.exit(1)

    print(f"[+] Assembled {count} instructions, {len(encoding)} bytes\n")
    return bytes(encoding)


def print_shellcode(shellcode: bytes) -> None:
    BYTES_PER_LINE = 16
    chunks = [shellcode[i : i + BYTES_PER_LINE] for i in range(0, len(shellcode), BYTES_PER_LINE)]
    lines = ['b"' + "".join(f"\\x{b:02x}" for b in chunk) + '"' for chunk in chunks]
    print("[ Exploit-ready ]")
    print("shellcode  = " + lines[0])
    for line in lines[1:]:
        print("shellcode += " + line)
    print()

    if shellcode[0] == 0xCC:
        print("[!] DEBUG MODE: shellcode starts with INT3 — do not use in production")
        print()


def check_size(shellcode: bytes, max_size: int) -> None:
    remaining = max_size - len(shellcode)
    if remaining < 0:
        print(f"[!] Size exceeded: {len(shellcode)} bytes / {max_size} limit ({-remaining} bytes over)")
    else:
        print(f"[+] Size ok: {len(shellcode)} / {max_size} bytes ({remaining} bytes remaining)")
    print()


def check_badchars(shellcode: bytes, badchars: set) -> None:
    found = [(i, b) for i, b in enumerate(shellcode) if b in badchars]
    if found:
        insn_map = {}
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        for insn in cs.disasm(shellcode, 0):
            for i in range(insn.size):
                insn_map[insn.address + i] = f"{insn.mnemonic} {insn.op_str}".strip()

        print(f"[!] Bad characters found ({len(found)}):")
        for offset, byte in found:
            insn = insn_map.get(offset, "unknown")
            print(f"    offset {offset:#06x}  \\x{byte:02x}  —  {insn}")
    else:
        chars = ", ".join(f"\\x{b:02x}" for b in sorted(badchars))
        print(f"[+] No bad characters detected  (checked: {chars})")


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_asm = os.path.join(script_dir, "asm", "revshell.asm")

    parser = argparse.ArgumentParser(
        description="Keystone x86 assembler — assembles an .asm file and outputs exploit-ready shellcode."
    )
    parser.add_argument(
        "file",
        nargs="?",
        default=default_asm,
        help="path to .asm file (default: revshell.asm)",
    )
    parser.add_argument(
        "-i",
        dest="lhost",
        metavar="IP",
        help="LHOST IP address — substitutes LHOST_DWORD in the asm",
    )
    parser.add_argument(
        "-p",
        dest="lport",
        metavar="PORT",
        type=int,
        help="LPORT port number — substitutes LPORT_WORD in the asm",
    )
    parser.add_argument(
        "-b",
        dest="badchars",
        metavar="CHARS",
        default="",
        help='bad character list in msfvenom format, e.g. "\\x00\\x0a\\x0d"',
    )
    parser.add_argument(
        "-m",
        dest="max_size",
        metavar="BYTES",
        type=int,
        help="warn if shellcode exceeds this size in bytes",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="prepend INT3 (0xcc) to the shellcode for WinDbg debugging",
    )

    args = parser.parse_args()

    badchars = parse_badchars(args.badchars)
    badchars.add(0x00)  # null is always a bad char

    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    print(f"[*] Assembling: {args.file}\n")
    shellcode = assemble(args.file, args.lhost, args.lport, args.debug)

    print_shellcode(shellcode)

    if args.max_size is not None:
        check_size(shellcode, args.max_size)

    check_badchars(shellcode, badchars)
