[BITS 32]

global _start


;int MessageBoxA(
;  HWND hWnd,
;  LPCSTR lpText,
;  LPCSTR lpCaption,
;  UINT uType
;)


_start:

	mov eax, 0x7e4507ea	; WinExec
	xor ecx, ecx
	
	push ecx
	push 0x21646c72
	push 0x6f57206f
	push 0x6c6c6548
	mov ebx, esp	; "Hello World!"


	mov edx, 0x01012265
	sub edx, 0x01010101
	push edx
	push 0x6574696F
	push 0x6C707845
	mov edx, esp	; "Exploited!"


	push ecx
	push ebx
	push edx
	push ecx
	call eax


	mov eax, 0x7c81cafa	; ExitProcess
	push ecx
	call eax
