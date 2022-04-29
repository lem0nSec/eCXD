%define sys_execve 0xb
%define sys_exit 0x1

section .data
        shell db "/bin/sh"

section .text
        global _start

_start:
        mov eax, sys_execve
        mov ebx, shell          ; ebx (const char *filename)
        int 0x80
        jmp _exit

_exit:
        mov eax, sys_exit
        xor ebx, ebx
        int 0x80
