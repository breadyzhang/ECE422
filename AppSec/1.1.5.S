.global _main
.section .text

_main:

push    %ebp
mov     %esp,%ebp

# Your code here
push $0x0B
popl %eax
movl $file_location, %ebx
movl $0x0, %ecx
xorl %edx, %edx

int $0x80

leave
ret

file_location:
	.string "/bin/sh"

