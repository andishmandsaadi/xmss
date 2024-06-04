import hashlib
import os
from hashlib import sha256
from pprint import pprint

WOTS_N = 32  # Hash output size (SHA-256)
WOTS_W = 16  # Winternitz parameter
WOTS_L1 = 256 // WOTS_W  # Number of message blocks
WOTS_L2 = (WOTS_W - 1) // WOTS_W + 1  # Number of checksum blocks
WOTS_L = WOTS_L1 + WOTS_L2  # Total number of blocks
def wots_hash(data):
    return hashlib.sha256(data).digest()

def chain(out, start, steps, bitmask):
    for i in range(start, steps):
        out = bytes([b ^ bm for b, bm in zip(out, bitmask)])
        out = wots_hash(out)
    return out

def wots_gen_key(bitmask):
    private_key = [os.urandom(WOTS_N) for _ in range(WOTS_L)]
    public_key = [chain(pk, 0, WOTS_W - 1, bitmask) for pk in private_key]
    return private_key, public_key
def to_base_w(value, out_len):
    """Converts an array of bytes to base-W values."""
    # Initialize variables
    bit_values = []
    bits_in_accumulator = 0
    accumulator = 0

    # Process each byte in the input value
    for byte in value:
        # Add byte to accumulator
        accumulator = (accumulator << 8) | byte
        bits_in_accumulator += 8

        # Extract base-W values as long as we have enough bits in the accumulator
        while bits_in_accumulator >= WOTS_W:
            bits_in_accumulator -= WOTS_W
            bit_values.append((accumulator >> bits_in_accumulator) & (WOTS_W - 1))

    # Ensure the output is of the desired length, truncating or padding with zeros as necessary
    return bit_values[:out_len]

def wots_sign(message, private_key, bitmask):
    hash_value = wots_hash(message.encode())
    base_w_msg = to_base_w(hash_value, WOTS_L1)

    # Calculate the checksum using the proper base-w representation
    checksum = sum(WOTS_W - 1 - b for b in base_w_msg)
    # Convert the checksum to base-w
    base_w_csum = to_base_w(checksum.to_bytes((checksum.bit_length() + 7) // 8, 'big'), WOTS_L2)

    # Generate the signature by iterating over both the message and checksum parts
    signature = [chain(private_key[i], 0, step, bitmask) for i, step in enumerate(base_w_msg + base_w_csum)]
    return signature


def wots_verify(signature, message, public_key, bitmask):
    hash_value = wots_hash(message.encode())
    base_w_msg = to_base_w(hash_value, WOTS_L1)

    # Recalculate the checksum based on the message part
    checksum = sum(WOTS_W - 1 - b for b in base_w_msg)
    base_w_csum = to_base_w(checksum.to_bytes((checksum.bit_length() + 7) // 8, 'big'), WOTS_L2)

    # Verify each chain in the signature against the public key
    for i, sig_block in enumerate(signature):
        # Calculate the expected number of steps to reach the public key value
        steps = WOTS_W - 1 - (base_w_msg[i] if i < WOTS_L1 else base_w_csum[i - WOTS_L1])
        verify = chain(sig_block, 0, steps, bitmask)

        # Compare the result of chaining to the corresponding public key block
        if verify != public_key[i]:
            return False

    return True

def l_tree(public_key, hash_function):
    # Simulate an L-Tree where leaves are the public keys of WOTS+
    nodes = list(public_key)  # Copy to avoid modifying the original list
    while len(nodes) > 1:
        new_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else left
            new_level.append(hash_function(left + right))
        nodes = new_level
    return nodes[0]  # The root of the L-Tree

def hash256(input_bytes):
    if isinstance(input_bytes, str):
        # If the input is a string, encode it to bytes. This allows the function to handle both bytes and string inputs.
        input_bytes = input_bytes.encode('utf-8')
    return sha256(input_bytes).hexdigest()


# Function to verify a signature
def verify_signature(message_hash, proof_path, merkle_root, secret_key_hash):
    current_hash = secret_key_hash
    for sibling_hash, position in proof_path:
        if position == 0:
            current_hash = hash256(current_hash + sibling_hash)
        else:  # 1
            current_hash = hash256(sibling_hash + current_hash)
    return current_hash == merkle_root

# Function to build the Merkle tree given the leaves
def build_merkle_tree(leaves):
    if len(leaves) % 2 != 0:
        leaves.append(leaves[-1])  # Duplicate the last leaf if odd number of leaves
    nodes = [leaves]
    current_level = leaves
    while len(current_level) > 1:
        new_level = []
        for i in range(0, len(current_level), 2):
            new_level.append(hash256(current_level[i] + current_level[i+1]))
        nodes.append(new_level)
        current_level = new_level
    return nodes  # Return all levels of the tree for reference

def xmss_gen_keys(number_of_keys, bitmask):
    wots_keys = [wots_gen_key(bitmask) for _ in range(number_of_keys)]
    l_tree_roots = [l_tree(pk, wots_hash) for _, pk in wots_keys]
    print(l_tree_roots)
    exit()
    # Building the XMSS Merkle tree from L-Tree roots
    xmss_tree = build_merkle_tree(l_tree_roots)
    return wots_keys, xmss_tree

def xmss_verify(wots_signature,wots_keys, message, xmss_tree, proof_path, index, bitmask):
    # Extract components
    _, wots_public_key = wots_keys[index]
    # WOTS+ verify
    is_valid_wots = wots_verify(wots_signature, message, wots_public_key, bitmask)
    if not is_valid_wots:
        return False

    # Reconstruct the L-Tree leaf
    l_tree_root = l_tree(wots_public_key, wots_hash)
    message_hash = hash256(message)

    # Verify the L-Tree root against the XMSS Merkle tree root using the authentication path
    return verify_signature(message_hash, proof_path, xmss_tree[-1][0], l_tree_root)

def generate_proof_path_with_direction(nodes, leaf_index):
    path = []
    for level in nodes[:-1]:  # Exclude the root
        sibling_index = leaf_index ^ 1  # XOR to find the sibling index
        direction = 0 if leaf_index % 2 == 0 else 1
        path.append((level[sibling_index], direction))
        leaf_index //= 2  # Move up to the parent index for the next level
    return path

def xmss_sign(message, wots_keys, xmss_tree, index, bitmask):
    # Select the WOTS+ keypair
    private_key, _ = wots_keys[index]

    # Sign the message using WOTS+
    wots_signature = wots_sign(message, private_key, bitmask)

    # Generate the authentication path for the given index
    proof_path = generate_proof_path_with_direction(xmss_tree, index)

    # Return the XMSS signature
    return wots_signature, proof_path, index

# Generate XMSS keys
number_of_keys = 8  # Number of WOTS+ keypairs
bitmask = os.urandom(WOTS_N)
wots_keys, xmss_tree = xmss_gen_keys(number_of_keys, bitmask)

message = "Hello, XMSS!"
random_index = 4
signature, proof_path, index = xmss_sign(message, wots_keys, xmss_tree, random_index, bitmask)
print(len(signature))
is_valid = xmss_verify(signature, wots_keys, message, xmss_tree, proof_path, index, bitmask)
print("Verification passed:", is_valid)

