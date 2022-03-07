from Crypto.Util import number
import math
from functools import reduce
from Crypto.PublicKey import RSA
from pbp import decrypt

e = 65537 # From assignment description

# From discussion
def get_d(p, q, e):
    totient = (p-1)*(q-1)
    return number.inverse(e, totient)


# From https://facthacks.cr.yp.to/product.html
def product_tree(X):
    tree = [X]
    while len(X) > 1:
        X = [reduce((lambda x, y: x*y), X[i*2:(i+1)*2]) for i in range((len(X) + 1)//2)]
        tree.append(X)
    return tree

def remainder_tree(prod_tree):
    limit = len(prod_tree[0])
    X = prod_tree.pop()
    tree = [X]
    while len(X) < limit:
        mods = prod_tree.pop()
        X = [X[i//2] % (mods[i]**2) for i in range(len(mods))]
        tree.append(X)
    return tree


def get_gcds(moduli):
    
    prod_tree = product_tree(moduli)
    # print(prod_tree)
    rem_tree = remainder_tree(prod_tree)
    # print(rem_tree)

    z = rem_tree[-1]
    gcds = [math.gcd(z[i]//moduli[i], moduli[i]) for i in range(len(moduli))]
    return gcds



# Read in moduli (from stackoverflow)
moduli = []
with open("moduli.hex") as f:
    #i = 0
    for line in f:
        moduli.append(int(line, 16))
        #i += 1
        #if i > 1000:
            #break

# Read ciphertext
ciphertext = open("3.2.4_ciphertext.enc.asc").read()
print(ciphertext)

gcds = get_gcds(moduli)
for i,gcd in enumerate(gcds):
    if gcd == 1:
        continue
    
    n = moduli[i]
    p = gcd
    q = n // p
    
    # print("N:", moduli[i])
    # print("p:", gcd)
    # print("q:", moduli[i] // gcd)
    assert n == p * q
    
    d = get_d(p, q, e)
    key = RSA.construct((n, e, d, p, q))
    try:
        plaintext = decrypt(key, ciphertext)
        print(plaintext)
    except:
        continue
