import sys

if len(sys.argv) != 5:
    print("usage: ciphertext_file key_file module_file output_file")
    exit()

# m = c^d mod(n)
# c = ciphertext
# d = secret
# n = public modulus

ciphertext = open(sys.argv[1]).read().strip()
key = open(sys.argv[2]).read().strip()
modulus = open(sys.argv[3]).read().strip()

int_ciphertext = int(ciphertext, 16)
int_key = int(key,16)
int_modulus = int(modulus, 16)

int_msg = pow(int_ciphertext, int_key, int_modulus)
msg = hex(int_msg)[2:]

f = open(sys.argv[4],"w")
f.write(msg)
f.flush()
f.close()
