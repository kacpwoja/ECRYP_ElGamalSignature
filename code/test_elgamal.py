import elgamal
from hashlib import sha256

""" Testing the elgamal module """

if __name__ == "__main__":
    # Documents to sign
    msgs = ["ECRYP", "kwojakow", "ElGamal Digital Signature", "lorem ipsum", "dorime interimo adapare dorime ameno ameno latire latiremo dorime"]
    # Hash function
    hfun = sha256()
    # Bit Length
    N = 32

    # Testing the signatures for the documents
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