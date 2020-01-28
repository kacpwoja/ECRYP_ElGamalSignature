from Crypto.Util import number as num
from random import randint
from math import gcd

def generate_system(key_length, hash_function):
    p = 4
    while not num.isPrime(p):
        pp = num.getPrime(key_length-1)
        p = pp*2+1
    g = randint(2, p-1)
    while (p-1)%g == 1:
        g = randint(2, p-1)
    system = {
        "N": key_length,
        "p": p,
        "H": hash_function,
        "g": g  
    }
    return system

def generate_keys(system):
    x = randint(1, system["p"]-2)
    y = pow(system["g"], x, system["p"])

    return x, y

def sign(system, message, private_key):
    s = 0
    H = system["H"].copy()
    H.update(message.encode())
    hash = int(H.hexdigest(), 16)
    while s == 0:
        k = randint(2,system["p"])
        while gcd(k, system["p"]-1) != 1:
            k = randint(2,system["p"])
        r = pow(system["g"], k, system["p"])
        s = ((hash - private_key*r) * num.inverse(k, system["p"]-1))%(system["p"]-1)

    return r,s

        

def verify(system, message, signature, public_key):
    if signature[0] <= 0 or signature[1] <= 0 or signature[0] >= system["p"] or signature[1] >= (system["p"]-1):
        return False
    
    H = system["H"].copy()
    H.update(message.encode())
    hash = int(H.hexdigest(), 16)

    g = system["g"]
    p = system["p"]
    r,s = signature
    y = public_key

    l = pow(g,hash,p)
    r = pow(y, r, p)%p * pow(r, s, p)%p

    return l == r