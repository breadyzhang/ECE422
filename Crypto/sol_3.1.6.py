import sys

if len(sys.argv) != 3:
    print("usage: file.txt, output_file")
    exit()

text = open(sys.argv[1]).read().strip()
bytes_text = text.encode('ascii')
mask = 0x3FFFFFFF
outHash = 0
for byte in bytearray(bytes_text):
    intermediate_value = ((byte ^ 0xCC) << 24) | ((byte ^ 0x33) << 16) | ((byte ^ 0xAA) << 8) | (byte ^ 0x55)
    outHash = (outHash & mask) + (intermediate_value & mask)
# print(hex(outHash))

f = open(sys.argv[2],"w")
f.write(hex(outHash)[2:])
