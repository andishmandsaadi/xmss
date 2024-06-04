from hashlib import sha256

# Function to compute the SHA-256 hash of a given input
def hash(input):
    return sha256(input.encode('utf-8')).hexdigest()

# Generate 8 secret keys for the leaves of the Merkle tree
secret_keys = [f"secret_key_{i}" for i in range(1, 9)]

# Compute the hash of each secret key to represent the leaves of the Merkle tree
leaves = [hash(key) for key in secret_keys]

# Function to build the Merkle tree given the leaves
def build_merkle_tree(leaves):
    nodes = leaves
    while len(nodes) > 1:
        new_level = []
        for i in range(0, len(nodes), 2):
            new_level.append(hash(nodes[i] + nodes[i+1]))
        nodes = new_level
    return nodes[0], leaves  # Return the Merkle root and the leaves for reference

# Build the Merkle tree and get the root and leaves
merkle_root, leaves = build_merkle_tree(leaves)

# Sign a message using the first secret key and generate the proof path
message = "hello"
message_hash = hash(message)

# Since we're using the first secret key, we'll manually construct the proof path for simplicity
# For a larger tree or different leaf, this would be more complex
proof_path = [
    leaves[1],  # Sibling of the first leaf
    hash(leaves[2] + leaves[3]),  # Parent's sibling
    hash(hash(leaves[4] + leaves[5]) + hash(leaves[6] + leaves[7]))  # Next level's parent's sibling
]

# Function to verify a message signature using the Merkle root and the proof path
def verify_signature(message_hash, proof_path, merkle_root, secret_key):
    current_hash = hash(secret_key)
    for sibling_hash in proof_path:
        current_hash = hash(current_hash + sibling_hash)
    return current_hash == merkle_root

# Verify the signature of the message
signature_valid = verify_signature(message_hash, proof_path, merkle_root, secret_keys[0])
print(signature_valid)
merkle_root, leaves, proof_path, signature_valid
