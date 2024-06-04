import hashlib
import os

WOTS_N = 32  # Length of hash output (SHA-256)
WOTS_W = 16  # Winternitz parameter
WOTS_L = (256 + WOTS_W - 1) // WOTS_W  # Number of chains

def wots_hash(data):
    return hashlib.sha256(data).digest()

def wots_gen_chain(seed, chainlen):
    out = seed
    for _ in range(chainlen):
        out = wots_hash(out)
    return out

def wots_gen_keypair():
    private_key = [os.urandom(WOTS_N) for _ in range(WOTS_L)]
    public_key = [wots_gen_chain(seed, WOTS_W - 1) for seed in private_key]
    return public_key, private_key

def wots_sign(message, private_key):
    hash_value = wots_hash(message.encode())
    signature = []

    for i in range(WOTS_L):
        chainlen = (hash_value[i // 2] >> (4 * (i % 2))) & (WOTS_W - 1)
        signature.append(wots_gen_chain(private_key[i], chainlen))

    return signature

def wots_verify(signature, message, public_key):
    hash_value = wots_hash(message.encode())
    for i in range(WOTS_L):
        chainlen = WOTS_W - 1 - ((hash_value[i // 2] >> (4 * (i % 2))) & (WOTS_W - 1))
        verify = wots_gen_chain(signature[i], chainlen)
        if verify != public_key[i]:
            return False
    return True


public_key, private_key = wots_gen_keypair()
message = "Test message"
signature = wots_sign(message, private_key)
valid = wots_verify(signature, message, public_key)
print("Signature is", "valid" if valid else "invalid")
