import sys
import urllib.request, urllib.error

def get_status(url):
    try:
        resp = urllib.request.urlopen(url)
        return resp.status
    except urllib.error.HTTPError as e:
        assert e.code != 400, "Incorrect format"
        return e.code

WRONG_PADDING = 500
WRONG_MSG = 404
CORRECT = 200
BLOCK_SIZE = 16

input_hex = open(sys.argv[1]).read().strip()
iv = bytearray.fromhex(input_hex[:32])
ciphertext = bytearray.fromhex(input_hex[32:])

def pad(msg):
    n = len(msg) % 16
    return msg + ''.join(chr(i) for i in range(16, n, -1))

def oracle(hash_hex):
    assert type(hash_hex) == str
    status = get_status("http://192.17.103.142:8080/mp3/fz8/?" + hash_hex);
    return status

def hack_block(prev_block, block):
    assert type(prev_block) == bytearray
    assert type(block) == bytearray

    plainblock = bytearray(16)

    for i in range(16)[::-1]:
        # Calculate suffix for guess at byte i
        suffix = bytearray(16 - (i+1))
        padding = b''
        for j,k in enumerate(range(i+1, 16)):
            p = 0x10 - j - 1
            padding += p.to_bytes(1, "big") 
            suffix[j]  = p ^ prev_block[k] 
            suffix[j] ^= plainblock[k]
        # print("padding:", padding.hex())
        # print("suffix:", suffix.hex())
         
        # Find guess g for byte i
        g = -1
        while(True):
            g += 1
            
            # If we found nothing, then original -> 0x10
            if g == 256:
                g = prev_block[i]
            else:
                # assert g < 256 and g >= 0, "g = " + str(g)
            
                original = prev_block[i]
                if g == original:
                    continue
            
                # Develop a test query
                test = prev_block[:i]
                test += g.to_bytes(1, "big") + suffix
                test += block
                assert len(test) == 32
            
                # print((g.to_bytes(1, "big") + suffix).hex())

                status = oracle(test.hex())
                if status == WRONG_PADDING:
                    continue
            
                assert status == WRONG_MSG

            # We found the correct g!
            # print("g:", hex(g))
            plainblock[i] = prev_block[i] ^ g ^ 0x10
            # print("plainblock:", plainblock.hex())
            break

    # print(plainblock.hex())
    return plainblock

# plaintext = hack_block(ciphertext[-32:-16], ciphertext[-16:])
# print("Plaintext:", plaintext.decode())

plaintext = ""
input_bytes = bytearray.fromhex(input_hex)
for i in range(len(input_bytes) // 16 - 1):
    prev_block = input_bytes[i*16:(i+1)*16]
    block      = input_bytes[(i+1)*16:(i+2)*16]
    plainblock = hack_block(prev_block, block).decode()
    print(plainblock)
    plaintext = plaintext + plainblock
print(plaintext)

f = open("tmp.bin", 'w')
f.write(plaintext)
f.flush()
f.close()
