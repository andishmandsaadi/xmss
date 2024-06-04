from hashlib import sha256
from pprint import pprint

# Function to compute the SHA-256 hash of a given input
def hash256(input):
    return sha256(input.encode('utf-8')).hexdigest()

# Number of secret keys (dynamic)
num_secret_keys = 256

# Generate secret keys
secret_keys = [f"secret_key_{i}" for i in range(0, num_secret_keys)]
pprint(secret_keys)

# Compute the hash of each secret key to represent the leaves of the Merkle tree
leaves = [hash256(key) for key in secret_keys]
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
# pprint(nodes)
merkle_root = nodes[-1][0]  # The last element in nodes is the root



def calculateNumberFromHash(hash_value):

    # Convert the hash value to bytes for easier manipulation
    hash_bytes = bytes.fromhex(hash_value)

    # Define the number of parts we want to split the hash into
    num_parts = 32
    part_length = len(hash_bytes) // num_parts

    # Split the hash into 32 parts
    hash_parts = [hash_bytes[i * part_length:(i + 1) * part_length] for i in range(num_parts)]

    # Convert each part back to hex for easy display or use in key selection
    hash_parts_hex = [part.hex() for part in hash_parts]

    hash_parts_hex
    # Convert each part to its decimal representation (range 0-255)
    hash_parts_decimal = [int(part, 16) for part in hash_parts_hex]

    return hash_parts_decimal

def generate_proof_path_with_direction(nodes, leaf_index):
    path = []
    for level in nodes[:-1]:  # Exclude the root
        sibling_index = leaf_index ^ 1  # XOR to find the sibling index
        direction = 0 if leaf_index % 2 == 0 else 1
        path.append((level[sibling_index], direction))
        leaf_index //= 2  # Move up to the parent index for the next level
    return path


# Sign a message
message = "Hello, world!"
message_hash = hash256(message)

# Function to verify a signature
def verify_signature(message_hash, selected_keys, proof_path, merkle_root, secret_key_hash):
    verifyStatus = True
    for val in selected_keys:
        current_hash = secret_key_hash[val]
        for sibling_hash, position in proof_path[val]:
            if position == 0:
                current_hash = hash256(current_hash + sibling_hash)
            else:  # 1
                current_hash = hash256(sibling_hash + current_hash)
        if current_hash != merkle_root:
           verifyStatus = False
    return verifyStatus
selected_keys = calculateNumberFromHash(message_hash)
# print(selected_keys)
proof_path = {}
secret_key_hash = {}
for val in selected_keys:
    random_secret_key = secret_keys[val]
    # Generate proof path for the selected secret key
    proof_path[val] = generate_proof_path_with_direction(nodes, val)
    # Verify the signature
    secret_key_hash[val] = hash256(random_secret_key)
# pprint(proof_path)
signature_valid = verify_signature(message_hash,selected_keys, proof_path, merkle_root, secret_key_hash)
print(signature_valid)
