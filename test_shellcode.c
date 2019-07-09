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
	if (argc < 2) {
		printf("Usage: test_shellcode shellcode.bin\n");
		exit(1);
	}
	
	int fd = open(argv[1], O_RDONLY);
	if (fd <= 0) {
		perror("Open");
		exit(1);
	}

	struct stat st;
	if (fstat(fd, &st) == -1) {
		perror("fstat");
		exit(1);			
	}
	
	shell_code_exec shell = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (shell == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	
	printf("Mapped Address: %p\n", shell);
	printf("Shell result: %d\n", shell());

	return 0;
}

