#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WOTS_N 32 // Hash output size (SHA-256)
#define WOTS_W 16 // Winternitz parameter
#define WOTS_L1 (256 / WOTS_W) // Number of message blocks
#define WOTS_L2 ((WOTS_W - 1) / WOTS_W + 1) // Number of checksum blocks
#define WOTS_L (WOTS_L1 + WOTS_L2) // Total number of blocks

// Hash function wrapper
void wots_hash(unsigned char *out, const unsigned char *in, size_t len) {
    SHA256(in, len, out);
}

// Chain function
void chain(unsigned char *out, const unsigned char *in, int start, int steps, const unsigned char *bitmask) {
    memcpy(out, in, WOTS_N);
    for (int i = start; i < steps; ++i) {
        for (int j = 0; j < WOTS_N; ++j) {
            out[j] ^= bitmask[j]; // Apply bitmask
        }
        wots_hash(out, out, WOTS_N);
    }
}

// Convert message to base-w
void to_base_w(unsigned int *out, const unsigned char *in, int out_len) {
    int total_bits = 0;
    int total = 0;
    int bits = 0;
    for (int i = 0; i < out_len; i++) {
        if (bits == 0) {
            total = in[total_bits / 8];
            bits += 8;
            total_bits += 8;
        }
        bits -= WOTS_W;
        out[i] = (total >> bits) & (WOTS_W - 1);
    }
}

// Key generation
void wots_gen_key(unsigned char public_key[WOTS_L][WOTS_N], unsigned char private_key[WOTS_L][WOTS_N], const unsigned char *bitmask) {
    for (int i = 0; i < WOTS_L; ++i) {
        for (int j = 0; j < WOTS_N; ++j) {
            private_key[i][j] = rand() % 256; // Random private key (use a secure RNG in production)
        }
        chain(public_key[i], private_key[i], 0, WOTS_W - 1, bitmask);
    }
}

// Signature generation
// void wots_sign(unsigned char signature[WOTS_L][WOTS_N], const unsigned char *message, const unsigned char private_key[WOTS_L][WOTS_N], const unsigned char *bitmask) {
void wots_sign(unsigned char signature[WOTS_L][WOTS_N], const unsigned char *message, const unsigned char private_key[WOTS_N], const unsigned char *bitmask){

    unsigned char hash[WOTS_N];
    unsigned int base_w_msg[WOTS_L1];
    wots_hash(hash, message, strlen((char *)message));
    to_base_w(base_w_msg, hash, WOTS_L1);

    // Compute checksum
    unsigned int csum = 0;
    for (int i = 0; i < WOTS_L1; ++i) {
        csum += WOTS_W - 1 - base_w_msg[i];
    }
    unsigned int base_w_csum[WOTS_L2];
    to_base_w(base_w_csum, (unsigned char *)&csum, WOTS_L2);

    for (int i = 0; i < WOTS_L1; ++i) {
        chain(signature[i], private_key[i], 0, base_w_msg[i], bitmask);
    }
    for (int i = 0; i < WOTS_L2; ++i) {
        chain(signature[WOTS_L1 + i], private_key[WOTS_L1 + i], 0, base_w_csum[i], bitmask);
    }
}

// Signature verification
int wots_verify(const unsigned char signature[WOTS_L][WOTS_N], const unsigned char *message, const unsigned char public_key[WOTS_L][WOTS_N], const unsigned char *bitmask) {
    unsigned char hash[WOTS_N];
    unsigned int base_w_msg[WOTS_L1];
    wots_hash(hash, message, strlen((char *)message));
    to_base_w(base_w_msg, hash, WOTS_L1);

    // Compute checksum
    unsigned int csum = 0;
    for (int i = 0; i < WOTS_L1; ++i) {
        csum += WOTS_W - 1 - base_w_msg[i];
    }
    unsigned int base_w_csum[WOTS_L2];
    to_base_w(base_w_csum, (unsigned char *)&csum, WOTS_L2);

    unsigned char verify[WOTS_N];
    for (int i = 0; i < WOTS_L1; ++i) {
        chain(verify, signature[i], base_w_msg[i], WOTS_W - 1, bitmask);
        if (memcmp(verify, public_key[i], WOTS_N) != 0) {
            return 0;
        }
    }
    for (int i = 0; i < WOTS_L2; ++i) {
        chain(verify, signature[WOTS_L1 + i], base_w_csum[i], WOTS_W - 1, bitmask);
        if (memcmp(verify, public_key[WOTS_L1 + i], WOTS_N) != 0) {
            return 0;
        }
    }
    return 1;
}


typedef struct {
    unsigned char hash[WOTS_N]; // Hash value for the node
} MerkleTreeNode;

typedef struct {
    unsigned char private_key[WOTS_L][WOTS_N]; // WOTS+ private keys
    MerkleTreeNode* merkle_tree;              // Entire Merkle tree
    int tree_height;                          // Height of the Merkle tree
} MSSPrivateKey;

typedef struct {
    unsigned char root[WOTS_N]; // Root hash of the Merkle tree (MSS public key)
} MSSPublicKey;

typedef struct {
    int index; // Index of the used WOTS+ key
    unsigned char wots_signature[WOTS_L][WOTS_N]; // WOTS+ signature
    unsigned char auth_path[WOTS_N][WOTS_N]; // Authentication path in the Merkle tree
} MSSSignature;

void build_merkle_tree(MerkleTreeNode* tree, int num_leaves, int tree_height) {
    int total_nodes = (1 << (tree_height + 1)) - 1;
    int first_leaf = (1 << tree_height) - 1;

    // Assuming the leaf nodes are already filled with the hashes of WOTS+ public keys
    // Now, compute the internal nodes of the tree
    for (int i = first_leaf - 1; i >= 0; --i) {
        unsigned char temp_hash[2 * WOTS_N];
        memcpy(temp_hash, tree[2 * i + 1].hash, WOTS_N);
        memcpy(temp_hash + WOTS_N, tree[2 * i + 2].hash, WOTS_N);
        wots_hash(tree[i].hash, temp_hash, 2 * WOTS_N);
    }
}

void get_auth_path(MerkleTreeNode* tree, unsigned char auth_path[][WOTS_N], int leaf_idx, int tree_height) {
    int node = leaf_idx + (1 << tree_height) - 1;

    for (int i = 0; i < tree_height; ++i) {
        int sibling_node = (node % 2 == 0) ? (node + 1) : (node - 1);
        memcpy(auth_path[i], tree[sibling_node].hash, WOTS_N);
        node /= 2;
    }
}


void mss_keygen(MSSPrivateKey* priv_key, MSSPublicKey* pub_key, int tree_height) {
    int total_nodes = (1 << (tree_height + 1)) - 1;
    int num_leaves = 1 << tree_height;
    priv_key->merkle_tree = malloc(total_nodes * sizeof(MerkleTreeNode));
    priv_key->tree_height = tree_height;

    // Initialize WOTS+ keys for each leaf and fill the leaf nodes
    unsigned char wots_public_key[WOTS_L][WOTS_N];
    unsigned char wots_private_key[WOTS_L][WOTS_N];
    unsigned char bitmask[WOTS_N] = {0}; // Example bitmask, should be generated securely

    for (int i = 0; i < num_leaves; ++i) {
        // Generate WOTS+ key pair
        wots_gen_key(wots_public_key, wots_private_key, bitmask);

        // Hash the WOTS+ public key to get the leaf node hash
        wots_hash(priv_key->merkle_tree[num_leaves - 1 + i].hash, (unsigned char*)wots_public_key, sizeof(wots_public_key));
    }

    // Build the Merkle tree
    build_merkle_tree(priv_key->merkle_tree, num_leaves, tree_height);

    // Set the public key (root of the tree)
    memcpy(pub_key->root, priv_key->merkle_tree[0].hash, WOTS_N);
}

void mss_sign(MSSSignature* signature, MSSPrivateKey* priv_key, const unsigned char* message, int index) {
    unsigned char bitmask[WOTS_N] = {0}; // In a real implementation, this should be a cryptographic random value

    // Ensure the index is valid
    if (index < 0 || index >= (1 << priv_key->tree_height)) {
        fprintf(stderr, "Invalid index for MSS signature\n");
        return;
    }

    // Sign the message using the selected WOTS+ private key
    // wots_sign(signature->wots_signature, message, priv_key->private_key[index], bitmask);
    wots_sign(signature->wots_signature, message, priv_key->private_key[index], bitmask);


    // Get the authentication path for the given index
    get_auth_path(priv_key->merkle_tree, signature->auth_path, index, priv_key->tree_height);

    signature->index = index;
}

void Reconstruct_leaf_hash(const unsigned char wots_signature[WOTS_L][WOTS_N], const unsigned char* message, unsigned char* leaf_hash) {
    unsigned char regenerated_pub_key[WOTS_L][WOTS_N];
    unsigned char hash[WOTS_N];
    unsigned char bitmask[WOTS_N] = {0}; // In a real implementation, this should be a cryptographic random value


    // Hash the message
    wots_hash(hash, message, strlen((char *)message));

    // Convert the hash to base-w
    unsigned int base_w_msg[WOTS_L1];
    to_base_w(base_w_msg, hash, WOTS_L1);

    // Reconstruct the WOTS+ public key
    for (int i = 0; i < WOTS_L; i++) {
        // The number of iterations to apply to the signature part to obtain the public key part
        unsigned int chainlen = WOTS_W - 1 - base_w_msg[i];
        chain(regenerated_pub_key[i], wots_signature[i], 0, chainlen, bitmask);
    }


    // Hash the regenerated WOTS+ public key to get the leaf hash
    wots_hash(leaf_hash, (unsigned char*)regenerated_pub_key, sizeof(regenerated_pub_key));
}

int mss_verify(MSSSignature* signature, MSSPublicKey* pub_key, const unsigned char* message, int tree_height) {
    // Verify the WOTS+ signature and reconstruct the leaf hash
    unsigned char leaf_hash[WOTS_N];
    unsigned char bitmask[WOTS_N] = {0}; // In a real implementation, this should be a cryptographic random value

    // if (!wots_verify(signature->wots_signature, message, /* wots public key */, /* bitmask */)) {
    //     return 0; // WOTS+ signature verification failed
    // }

    // Reconstruct the leaf hash from the WOTS+ signature
    Reconstruct_leaf_hash(signature->wots_signature, message, leaf_hash);

    // Reconstruct the Merkle tree path to compute the root
    unsigned char computed_node[WOTS_N];
    memcpy(computed_node, leaf_hash, WOTS_N);

    int node = signature->index;
    for (int i = 0; i < tree_height; i++) {
        unsigned char sibling_node[WOTS_N];
        memcpy(sibling_node, signature->auth_path[i], WOTS_N);

        // Determine the order of hashing for siblings
        if (node % 2 == 0) {
            // Current node is a left child
            wots_hash(computed_node, computed_node, WOTS_N); // Hash current node
            chain(computed_node, sibling_node, 0, 1, bitmask ); // Chain with sibling
        } else {
            // Current node is a right child
            chain(sibling_node, sibling_node, 0, 1, bitmask ); // Chain sibling
            wots_hash(computed_node, sibling_node, WOTS_N); // Hash with chained sibling
        }

        node /= 2; // Move up the tree
    }

    // Compare the computed root with the public key's root
    return memcmp(computed_node, pub_key->root, WOTS_N) == 0;
}

int main() {
    // Define the tree height
    int tree_height = 3;

    // Create and initialize MSS private and public keys
    MSSPrivateKey priv_key;
    MSSPublicKey pub_key;
    mss_keygen(&priv_key, &pub_key, tree_height);

    // Define a message to be signed
    const char* message = "Hello, world!";

    // Define the index of the WOTS+ key pair to use (e.g., 0 for the first key pair)
    int index = 0;

    // Create a signature
    MSSSignature signature;
    mss_sign(&signature, &priv_key, (const unsigned char*)message, index);

    // Verify the signature
    int is_valid = mss_verify(&signature, &pub_key, (const unsigned char*)message, tree_height);

    // Output the result of the verification
    if (is_valid) {
        printf("Signature is valid.\n");
    } else {
        printf("Signature is invalid.\n");
    }

    // Free allocated memory for the Merkle tree
    free(priv_key.merkle_tree);

    return 0;
}