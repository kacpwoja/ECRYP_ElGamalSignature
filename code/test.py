import elgamal
from hashlib import sha256

if __name__ == "__main__":
    msgs = ["ECRYP", "kwojakow", "ElGamal Digital Signature", "lorem ipsum", "dorime interimo adapare dorime ameno ameno latire latiremo dorime"]
    hfun = sha256()
    N = 32

    for msg in msgs:
        print("Message:")
        print(msg)

        elgsys = elgamal.generate_system(N, hfun)
        print("Generated system:")
        print(elgsys)

        keys = elgamal.generate_keys(elgsys)
        print("Generated key pair (x, y):")
        print(keys)

        sig = elgamal.sign(elgsys, msg, keys[0])
        print("Generated signature pair (r, s):")
        print(sig)

        is_valid = elgamal.verify(elgsys, msg, sig, keys[1])
        print("Is signature valid?")
        print(is_valid)