start:
    int3    ; Breakpoint for windbg, remove when not debugging

    mov ebp, esp            ; Emulate an actual function call
    add esp, 0xfffffdf0     ; Move esp so stack does not get clobbered

find_kernel32:
    xor ecx, ecx            ; ecx = 0

    ; In 32 bit windows the FS segment points to the TEB, and offset 0x30 points to the PEB
    mov esi, fs:[ecx+0x30]  ; esi = &(PEB) ([fs:0X30])

    ; The PEB at offset 0x0c points to the LDR (which stands for loader)
    mov esi, [esi+0x0c]     ; esi = PEB->Ldr

    ; The loader at offset 0x1c points to the InInitializationOrderModuleList
    ; We can walk this list to find loaded modules
    mov esi, [esi+0x1c]     ; esi = PEB->Ldr.InInitOrder

next_module:
    mov ebx, [esi+0x08]     ; ebp = InInitOrder[x].DllBase

    ; Unicode strings are itself a struct, which contains three members, length, maxlength, and buffer
    ; That's why the offset to the text is 0x20 instead of 0x1c (we need to move past the length and maxlength)
    mov edi, [esi+0x20]     ; ebp = InInitOrder[x].module_name (unicode)
    mov esi, [esi]          ; esi = InInitOrder[x].flink (next module)
    cmp [edi+12*2], cx      ; modulename[12] == 0? This check will match with kernel32.dll
    jne next_module         ; No: Try next module.

find_function_shorten:
    jmp find_function_shorten_bnc ; Short jump

find_function_ret:
    pop esi                         ; Pop the return address from the stack
    mov [ebp+0x04], esi             ; Save find_function address for later usage
    jmp resolve_symbols_kernel32    ; 

find_function_shorten_bnc:
    call find_function_ret          ; Relative call with negative offset

find_function:
    pushad                  ; Save all registers
    mov eax, [ebx+0x3c]     ; Get the address of the PE header (DllBase + PE header offset)
    mov edi, [ebx+eax+0x78] ; Get the Export Directory Table relative address (DllBase + PE header + relative address offset)
    add edi, ebx            ; Calculate the Export Directory Table virtual memory address (DllBase + relative address)

    mov ecx, [edi+0x18]     ; Get the number of exported names (EDT base + NumberOfNames offset)
    mov eax, [edi+0x20]     ; Get the relative address for the addresses of exported names array (EDT base + AddressOfNames offset)
    add eax, ebx            ; Calculate the virtual address for the address of names array
    mov [ebp-4], eax        ; Save address of names array virtual address to the stack

find_function_loop:
    jecxz find_function_finished    ; Jump to the end if ecx is 0 (we have parsed all symbol names)
    dec ecx                 ; Decrement our names counter
    mov eax, [ebp-4]        ; Retrieve the virtual address of the address of names array
    mov esi, [eax+ecx*4]    ; Get the relative address for the current symbol name
    add esi, ebx            ; Calculate the virtual address for the current symbol name

compute_hash:
    xor eax, eax    ; Set eax to null
    cdq             ; Uses null value in eax to set edx to null as well
    cld             ; Clear the direction flag in the EFLAGS register

compute_hash_again:
    lodsb ; Load the next byte from esi into al and automatically increment or decrement the register according to the DF flag

    test al, al         ; Check for null terminator
    jz compute_hash_finished   ; If zf is set, we found the null terminator, the hash has been computed
    ror edx, 0x0d       ; Rotate edx 13 bits to the right
    add edx, eax        ; Add the new byte to the accumulator
    jmp compute_hash_again    ; Next iteration

compute_hash_finished:

find_function_compare:
    cmp edx, [esp+0x24]         ; Compare the computed hash with the requested hash
    jnz find_function_loop  ; If it doesn't match get the next function

    mov edx, [edi+0x24]     ; Address of names ordinals relative address
    add edx, ebx            ; Address of names ordinals virtual address
    mov cx, [edx+2*ecx]     ; Extrapolate the function's ordinal
    mov edx, [edi+0x1c]     ; Address of functions relative address
    add edx, ebx            ; Address of functions virtual address
    mov eax, [edx+4*ecx]    ; Get the function relative address
    add eax, ebx            ; Get the function virtual address
    mov [esp+0x1c], eax     ; Overwrite the stack version of eax from pushad

find_function_finished:
    popad   ; Restore registers
    ret

resolve_symbols_kernel32:
    push 0x78b5b983     ; TerminateProcess hash
    call dword ptr [ebp+0x04]  ; Call find_function
    mov [ebp+0x10], eax ; Save TerminateProcess address for later usage

exec_shellcode:
    xor ecx, ecx
    push ecx        ; Pass an exit coded of 0 (successful exit)
    push 0xffffffff ; Pass a pseudo-handle to the current process
    call dword ptr [ebp+0x10]        ; Call TeriminateProcess
