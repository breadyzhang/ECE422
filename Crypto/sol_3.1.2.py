import sys

if len(sys.argv) != 4:
    print("usage: script, ciphertext_file, key_file, output_file")
    exit()
f = open(sys.argv[2])
key = f.read().strip()
f = open(sys.argv[1])
cipher = f.read().strip()

mapping = {}
for i in range(len(key)):
    mapping[key[i]] = chr(65+i)

mapping[' '] = ' '
msg = ""
for i in cipher:
    msg += mapping[i]

f = open(sys.argv[3],"w")
f.write(msg)
f.flush()
f.close()
