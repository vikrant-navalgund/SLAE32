// This skeleton/template has been taken from the excellent book 'Attacking Network Protocols' by James Forshaw.
// This gives a good framework to play around developing and debugging shellcode.

#include<stdlib.h>
#include<fcntl.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<stdio.h>
#include<unistd.h>

typedef int (*shell_code_exec)(void);

int main(int argc, char **argv) {
	if (argc < 3) {
		printf("Usage: test_shellcode shellcode.bin eggcode.bin\n");
		exit(1);
	}
	
	int fd1 = open(argv[1], O_RDONLY);
	if (fd1 <= 0) {
		perror("Open Shellcode");
		exit(1);
	}

	int fd2 = open(argv[2], O_RDONLY);
	if (fd2 <= 0) {
		perror("Open Eggcode");
		exit(1);
	}

	struct stat st1;
	if (fstat(fd1, &st1) == -1) {
		perror("fstat Shellcode");
		exit(1);			
	}

	struct stat st2;
	if (fstat(fd2, &st2) == -1) {
		perror("fstat Eggcode");
		exit(1);			
	}
	
	shell_code_exec shell = mmap(NULL, st1.st_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd1, 0);
	if (shell == MAP_FAILED) {
		perror("mmap shellcode");
		exit(1);
	}

	shell_code_exec eggcode = mmap(NULL, st2.st_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd2, 0);
	if (eggcode == MAP_FAILED) {
		perror("mmap eggcode");
		exit(1);
	}
	
	printf("[+] Egg hunter shellcode mapped address: %p\n", shell);
	printf("[+] Egg code + [payload] mapped address: %p\n", eggcode);
	printf("[+] Shell result: %d\n", shell());

	return 0;
}

