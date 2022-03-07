from Crypto.Util import number
import math

# From discussion
# b1_exp = b1*21024
# b2_exp = b2*21024
def getCRT(b1_exp, b2_exp, p1, p2, N):
    invOne = number.inverse(p2, p1)
    invTwo = number.inverse(p1, p2)
    return -(b1_exp * invOne * p2 + b2_exp * invTwo * p1) % N

def get_primes(e, b1, b2):
    b1_exp = b1 << 1024
    b2_exp = b2 << 1024

    while(True):
        # Find random primes
        p1 = number.getPrime(500)
        p2 = number.getPrime(500)
              
        if number.GCD(p1-1, e) != 1 or number.GCD(p2-1, e) != 1:
            continue
        p1p2 = p1*p2
        print('found primes:',p1,p2)
        # Compute b0
        b0 = getCRT(b1_exp, b2_exp, p1, p2, p1p2)
        print('b0:', b0)
        b = b0 - p1p2
        while(True):
            b += p1p2
            if math.log2(b) >= 1024:
                break
            
            n1 = b1_exp + b
            n2 = b2_exp + b
            q1 = n1 // p1
            q2 = n2 // p2

            if not number.isPrime(q1):
                continue
            if not number.isPrime(q2):
                continue
            if number.GCD(q1-1, e) != 1:
                continue
            if number.GCD(q2-1, e) != 1:
                continue

            return (n1, n2, p1, p2, q1, q2)

f1 = open("col1", "rb")
f2 = open("col2", "rb")

cert1 = f1.read()
cert2 = f2.read()
b1 = cert1[-128:]
b2 = cert2[-128:]
b1 = int.from_bytes(b1,"big")
b2 = int.from_bytes(b2,"big")
e = 65537
(n1,n2,p1,p2,q1,q2) = get_primes(e,b1,b2)
print("found numbers")
original = bytearray(open("out.cer", "rb").read())
with open("sol_3.2.5_factorsA.hex","w") as f:
    f.write(hex(p1)+'\n'+hex(q1))
    f.flush()
    f.close()
with open("sol_3.2.5_factorsB.hex","w") as f:
    f.write(hex(p2)+'\n'+hex(q2))
    f.flush()
    f.close()
# starting at 0xfe
with open("sol_3.2.5_certA.cer","wb") as f:
    #certA = original[:0xfe]+n1.to_bytes(256,"big")+original[0xfe+128:]
    certA = original
    certA[0xfe:0xfe+256] = bytearray(n1.to_bytes(256,"big"))
    f.write(certA)
    f.flush()
    f.close()
with open("sol_3.2.5_certB.cer", "wb") as f:
    #certB = original[:0xfe] + n2.to_bytes(256,"big")+original[0xfe+2
    certB = original
    certB[0xfe:0xfe+256] = bytearray(n2.to_bytes(256,"big"))
    f.write(certB)
    f.flush()
    f.close()
