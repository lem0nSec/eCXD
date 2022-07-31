[BITS 32]

global _start

        xor ebx, ebx
        push ebx
        push 0x6578652E
        push 0x636C6163
        mov ecx, esp
        push 1
        push ecx
        mov eax, 0x76062c21     ; WinExec: replace this with your WinExec address
        call eax
        xor ebx, ebx
        push ebx
        mov eax, 0x75fe7a10     ; ExitProcess: replace this with your ExitProcess address
        call eax
