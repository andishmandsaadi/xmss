from hashlib import sha256
import random
from pprint import pprint

# Function to compute the SHA-256 hash of a given input
def hash256(input):
    return sha256(input.encode('utf-8')).hexdigest()

# Number of secret keys (dynamic)
num_secret_keys = 8

# Generate secret keys
secret_keys = [f"secret_key_{i}" for i in range(1, num_secret_keys + 1)]
print('secret_keys :')
pprint(secret_keys)
# Compute the hash of each secret key to represent the leaves of the Merkle tree
leaves = [hash256(key) for key in secret_keys]
print('leaves :')
pprint(leaves)

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

# Build the Merkle tree
nodes = build_merkle_tree(leaves)
print('merkle_root :')
pprint(nodes)

merkle_root = nodes[-1][0]  # The last element in nodes is the root
print('merkle_root  :')
pprint(merkle_root)

# Select a random secret key for signing
# random_index = random.randint(0, num_secret_keys - 1)
random_index = 0
random_secret_key = secret_keys[random_index]
print('random_secret_key :')
pprint(random_secret_key)

def generate_proof_path_with_direction(nodes, leaf_index):
    path = []
    for level in nodes[:-1]:  # Exclude the root
        sibling_index = leaf_index ^ 1  # XOR to find the sibling index
        direction = 0 if leaf_index % 2 == 0 else 1
        path.append((level[sibling_index], direction))
        leaf_index //= 2  # Move up to the parent index for the next level
    return path

# Generate proof path for the selected secret key
proof_path = generate_proof_path_with_direction(nodes, random_index)
print('proof_path :')
pprint(proof_path)

# Sign a message
message = "asdfasdfasd"
message_hash = hash256(message)

# Function to verify a signature
def verify_signature(message_hash, proof_path, merkle_root, secret_key_hash):
    current_hash = secret_key_hash
    for sibling_hash, position in proof_path:
        if position == 0:
            current_hash = hash256(current_hash + sibling_hash)
        else:  # 1
            current_hash = hash256(sibling_hash + current_hash)
        print(current_hash)
    return current_hash == merkle_root

# Verify the signature
secret_key_hash = hash256(random_secret_key)
print('secret_key_hash :')
pprint(secret_key_hash)

signature_valid = verify_signature(message_hash, proof_path, merkle_root, secret_key_hash)
print(signature_valid)
num_secret_keys, random_secret_key, signature_valid
