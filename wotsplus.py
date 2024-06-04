import hashlib
import os
import math
from typing import List
from hmac import new as new_hmac

WOTS_N = 32  # Hash output size (SHA-256)
WOTS_W = 4  # Winternitz parameter
WOTS_L1 = int(256 / math.log2(WOTS_W))  # Ensure L1 is an integer
WOTS_L2 = math.ceil(math.log2(WOTS_L1 * (WOTS_W - 1)) / math.log2(WOTS_W))
WOTS_L = math.ceil(WOTS_L1) + WOTS_L2

print(WOTS_L1)
print(WOTS_L2)
print(WOTS_L)
exit()
def wots_hash(data):
    return hashlib.sha256(data).digest()

def chain(value, start, steps, bitmask):
    digestsize_bytes = int(math.ceil(256/ 8))

    for i in range(start, steps):
        bm = new_hmac(key=bitmask, msg=value, digestmod=hashlib.sha256).digest()
        tohash_b = (int.from_bytes(value, "big") ^
                    int.from_bytes(bm, "big"))
        tohash = tohash_b.to_bytes(digestsize_bytes, "big")
        value = wots_hash(tohash)

    return value

def numberToBase(num, base):
        if num == 0:
            return [0]

        digits = []

        while num:
            digits.append(int(num % base))
            num //= base

        return digits[::-1]

def wots_gen_key(bitmask):
    private_key = [os.urandom(WOTS_N) for _ in range(WOTS_L)]
    public_key = [chain(pk, 0, WOTS_W - 1, bitmask) for pk in private_key]
    return public_key, private_key

def checksumCalculate(values):
    # Inverse sum checksum
    result = 0

    for value in values:
        result += WOTS_W - 1 - value

    return result

def to_base_w(value):
    """Converts an array of bytes to base-W values."""
    msgnum = int.from_bytes(value, "big")

    bit_values = numberToBase(msgnum,WOTS_W)
    bit_values += [0] * (WOTS_L1 - len(bit_values))  # pad

    checksum = numberToBase(checksumCalculate(bit_values), WOTS_W)
    checksum += [0] * (WOTS_L2 - len(checksum))  # pad
    return bit_values + checksum

def wots_sign(message, private_key, bitmask):
    message_hash = wots_hash(message)
    base_w_msg = to_base_w(message_hash)

    # Generate the signature by iterating over both the message and checksum parts
    signature = [chain(private_key[i], 0, step, bitmask) for i, step in enumerate(base_w_msg)]
    return signature


def wots_verify(signature, message, public_key, bitmask):
    message_hash = wots_hash(message)
    base_w_msg = to_base_w(message_hash)

    # Verify each chain in the signature against the public key
    for i, sig_block in enumerate(signature):
        # Calculate the expected number of steps to reach the public key value
        steps = WOTS_W - 1 - base_w_msg[i]
        verify = chain(sig_block, 0, steps, bitmask)

        # Compare the result of chaining to the corresponding public key block
        if verify != public_key[i]:
            return False

    return True

bitmask = os.urandom(int(math.ceil( 256/ 8)))
for val in  wots_gen_key(bitmask)[1]:
    print(val.hex())
public_key, private_key = wots_gen_key(bitmask)
message = "My message in bytes format".encode("utf-8")
signature = wots_sign(message, private_key, bitmask)
valid = wots_verify(signature, message, public_key, bitmask)
print("Signature is", "valid" if valid else "invalid")