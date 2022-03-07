import sys
from Crypto.Cipher import AES

if len(sys.argv) != 5:
    print("usage: ciphertext_file key_file, iv_file, output_file")
    exit()

key = open(sys.argv[2]).read().strip()
bytes_key = bytes.fromhex(key)
iv = open(sys.argv[3]).read().strip()
bytes_iv = bytes.fromhex(iv)
ciphertext = open(sys.argv[1]).read().strip()
bytes_ciphertext = bytes.fromhex(ciphertext)

cipher = AES.new(bytes_key, AES.MODE_CBC, bytes_iv)
bytes_msg = cipher.decrypt(bytes_ciphertext)

f = open(sys.argv[4],"w")
f.write(bytes_msg.decode('utf-8'))
f.flush()
f.close()
