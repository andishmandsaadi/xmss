#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <mach/mach.h>

#define NUM_SECRET_KEYS 256
#define NUM_HASHES 32
#define HASH_LEN 64

clock_t start, end;
double cpu_time_used;

void hex_string_to_binary(const char* hexstr, unsigned char* buffer, size_t bufferLen) {
    char temp[3] = {0}; // Temporary buffer for two characters and null terminator.
    for (size_t i = 0; i < bufferLen; i++) {
        // Copy two hex digits and convert them to a single byte
        strncpy(temp, hexstr + (i * 2), 2);
        buffer[i] = (unsigned char)strtol(temp, NULL, 16);
    }
}
// Converts hash output to a hexadecimal string for easier comparison and printing
void to_hex_string(const unsigned char *hash, char *output, size_t len) {
    for (size_t i = 0; i < len; i++) {
        // sprintf(output + (i * 2), "%02x", hash[i]);
        snprintf(output + (i * 2), 3, "%02x", hash[i]);

    }
    output[len * 2] = '\0'; // Null-terminate string
}
void hash256(const unsigned char *input, size_t len, unsigned char output[HASH_LEN]) {
    SHA512(input, len, output);
}

// Helper function to concatenate two hashes and hash the result
void concatenate_and_hash(const unsigned char* hash1, const unsigned char* hash2, unsigned char* output) {
    char hex_output[HASH_LEN * 2 + 1]; // +1 for null terminator
    unsigned char concatenated[HASH_LEN * 2];
    memcpy(concatenated, hash1, HASH_LEN);
    memcpy(concatenated + HASH_LEN, hash2, HASH_LEN);

    unsigned char hash[HASH_LEN];
    char hex_str[HASH_LEN * 2 * 2 + 1];
    to_hex_string(concatenated, hex_str, HASH_LEN * 2);

    hash256((unsigned char *)hex_str, HASH_LEN * 2*2, hash);

    to_hex_string(hash, hex_output, HASH_LEN);

    hex_string_to_binary(hex_output, output, HASH_LEN);
}

void generate_secret_keys(char secret_keys[NUM_SECRET_KEYS][HASH_LEN * 2 + 1]) {
    // Placeholder for secret key generation logic
    // Here we're simplifying by using static strings for demonstration
    for (int i = 0; i < NUM_SECRET_KEYS; i++) {
        char input[20];
        // sprintf(input, "secret_key_%d", i);
        snprintf(input, sizeof(input), "secret_key_%d", i);
        unsigned char hash[HASH_LEN];
        hash256((unsigned char *)input, strlen(input), hash);
        to_hex_string(hash, secret_keys[i], HASH_LEN);
    }
}


unsigned char*** build_merkle_tree(char secret_keys[NUM_SECRET_KEYS][HASH_LEN * 2 + 1], int leavesCount) {

    int levels = 1;
    int temp = leavesCount;
    while (temp > 1) {
        temp = (temp + 1) / 2; // Account for odd number of leaves
        levels++;
    }

    unsigned char*** hashArray = malloc(levels * sizeof(unsigned char**));
    for (int i = 0; i < levels; i++) {
        int levelCount = (leavesCount + (1 << i) - 1) / (1 << i); // Calculate node count at each level
        hashArray[i] = malloc(levelCount * sizeof(unsigned char*));
        for (int j = 0; j < levelCount; j++) {
            hashArray[i][j] = malloc(HASH_LEN); // Allocate memory for each hash
        }
    }

    // Initialize leaf level with secret keys
    for (int j = 0; j < NUM_SECRET_KEYS; j++) {
        hex_string_to_binary(secret_keys[j], hashArray[0][j], HASH_LEN);
    }
    // Build the tree
    for (int i = 1; i < levels; i++) {
        int currentLevelCount = (leavesCount + (1 << (i - 1)) - 1) / (1 << (i - 1));
        for (int j = 0; j < currentLevelCount / 2; j++) {
            unsigned char concatenated[HASH_LEN * 2];
            memcpy(concatenated, hashArray[i - 1][2 * j], HASH_LEN);
            if (2 * j + 1 < currentLevelCount) { // Check if right sibling exists
                memcpy(concatenated + HASH_LEN, hashArray[i - 1][2 * j + 1], HASH_LEN);
            } else {
                memcpy(concatenated + HASH_LEN, hashArray[i - 1][2 * j], HASH_LEN); // Duplicate left if no right sibling
            }
            unsigned char hash[HASH_LEN];
            char hex_str[HASH_LEN * 2 * 2 + 1];
            to_hex_string(concatenated, hex_str, HASH_LEN * 2);

            hash256((unsigned char *)hex_str, HASH_LEN * 2*2, hash);

            char hex_output[HASH_LEN * 2 + 1]; // +1 for null terminator
            to_hex_string(hash, hex_output, HASH_LEN);

            hex_string_to_binary(hex_output, hashArray[i][j], HASH_LEN);
        }
        // For odd number of nodes, the last node is moved up to the next level without hashing
        if (currentLevelCount % 2 == 1) {
            memcpy(hashArray[i][currentLevelCount / 2], hashArray[i - 1][currentLevelCount - 1], HASH_LEN);
        }
    }
    return hashArray;
}
// Define a struct to hold a node in the path and its direction
typedef struct {
    unsigned char* hash; // Sibling hash
    int direction; // 0 for left, 1 for right
} ProofNode;

// Function to generate the proof path with direction
ProofNode* generate_proof_path_with_direction(unsigned char*** nodes, int total_levels, int leaf_index, int* path_length) {
    // Allocate memory for the path (maximum possible size is total_levels - 1)
    ProofNode* path = (ProofNode*)malloc((total_levels - 1) * sizeof(ProofNode));
    if (path == NULL) {
        // Handle memory allocation failure if needed
        return NULL;
    }

    *path_length = 0; // Initialize path length to 0
    for (int level = 0; level < total_levels - 1; level++) { // Exclude the root
        int sibling_index = leaf_index ^ 1; // XOR to find the sibling index
        int direction = (leaf_index % 2 == 0) ? 0 : 1; // Determine direction

        // Store the sibling hash and direction in the path
        path[*path_length].hash = nodes[level][sibling_index];
        path[*path_length].direction = direction;
        (*path_length)++; // Increment the path length

        leaf_index /= 2; // Move up to the parent index for the next level
    }

    return path;
}


// Verify the signature
int verify_signature(int hashParts[HASH_LEN], ProofNode** proof_paths, int path_length, const unsigned char* merkle_root, unsigned char* secret_keys[NUM_HASHES]) {
    int result = 1;
    for(int j=0; j< NUM_HASHES; j++) {
        unsigned char current_hash[HASH_LEN];
        unsigned char concatenated[HASH_LEN * 2];
        // Use memcpy to copy secret_key into current_hash
        memcpy(current_hash, secret_keys[j], HASH_LEN);
        for (int i = 0; i < path_length; ++i) {
            if (proof_paths[j][i].direction == 0) { // If the direction is 0, current_hash is left sibling
                concatenate_and_hash(current_hash, proof_paths[j][i].hash, concatenated);
            } else { // If the direction is 1, current_hash is right sibling
                concatenate_and_hash(proof_paths[j][i].hash, current_hash, concatenated);
            }
            memcpy(current_hash, concatenated, HASH_LEN);
        }
        // Compare the computed hash with the provided merkle root
        if(memcmp(current_hash, merkle_root, HASH_LEN) != 0){
            result = 0;
        }
    }

    return result;
}

// Function to convert a single hex char to an integer
int hexCharToInt(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

// Function to convert a hex string to a byte array
void hexStringToByteArray(const char* hexStr, unsigned char* byteArray, int byteArrayLength) {
    for (int i = 0; i < byteArrayLength; i++) {
        byteArray[i] = (hexCharToInt(hexStr[i*2]) << 4) + hexCharToInt(hexStr[i*2+1]);
    }
}

// Your target function adapted for C
void calculateNumberFromHash(const char* hash_value, int* hashPartsDecimal) {
    int hashLength = strlen(hash_value) / 2; // Length of the hash in bytes
    unsigned char* hashBytes = (unsigned char*)malloc(hashLength * sizeof(unsigned char));
    hexStringToByteArray(hash_value, hashBytes, hashLength);

    int numParts = 64;
    int partLength = hashLength / numParts;

    for (int i = 0; i < numParts; i++) {
        int value = 0;
        for (int j = 0; j < partLength; j++) {
            // Assuming you want to sum the byte values to get a single integer for each part
            value += hashBytes[i * partLength + j];
        }
        hashPartsDecimal[i] = value;
    }

    free(hashBytes);
}

size_t calculate_proof_path_array_size(ProofNode** arrayOfPaths, int numHashes, int pathLength) {
    size_t totalSize = 0;

    // Size of the pointers array
    totalSize += numHashes * sizeof(ProofNode*);

    // Add the size of each ProofNode in all paths
    for (int i = 0; i < numHashes; i++) {
        totalSize += pathLength * sizeof(ProofNode);
    }

    return totalSize;
}

int main() {
    printf("SHA512\n");
    start = clock();

    char secret_keys[NUM_SECRET_KEYS][HASH_LEN * 2 + 1];
    generate_secret_keys(secret_keys);
    // end = clock();

    // cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    // printf("Key generation took %f seconds to execute \n", cpu_time_used);
    // printf("Key size: %lu bytes\n", sizeof(secret_keys)); // For private or public key size
    // for (int i = 0; i < NUM_SECRET_KEYS; i++) {
    //     printf("Secret Key %d: %s\n", i + 1, secret_keys[i]);
    // }
    // start = clock();
    unsigned char*** merkel_tree = build_merkle_tree(secret_keys, NUM_SECRET_KEYS);
    end = clock();

    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Merkle tree generation took %f milli seconds to execute \n", cpu_time_used*1000);
    int levels = 1;
    int temp = NUM_SECRET_KEYS;
    while (temp > 1) {
        temp = (temp + 1) / 2;
        levels++;
    }
    size_t merkle_tree_size = 0;
    for (int i = 0; i < levels; i++) {
        int levelCount = (NUM_SECRET_KEYS + (1 << i) - 1) / (1 << i); // Nodes at this level
        merkle_tree_size += levelCount * sizeof(unsigned char*) + // For node pointers
                            levelCount * HASH_LEN; // For node data
    }
    printf("Merkle Tree total size: %lu  bytes\n", (merkle_tree_size + sizeof(secret_keys)));
    int path_length = 0; // This will hold the actual length of the generated path

    unsigned char* merkle_root = merkel_tree[levels - 1][0];

    // Convert the Merkle root to a hexadecimal string for printing
    char hex_merkle_root[HASH_LEN * 2 + 1]; // +1 for null terminator
    to_hex_string(merkle_root, hex_merkle_root, HASH_LEN);



    // Sign and verify a message
    char *message = "Hello, world!";
    unsigned char message_hash[HASH_LEN];
    hash256((unsigned char *)message, strlen(message), message_hash);
    char message_hash_hex[HASH_LEN * 2 + 1];
    to_hex_string(message_hash, message_hash_hex, HASH_LEN);

    int hashPartsDecimal[HASH_LEN];
    start = clock();
    calculateNumberFromHash(message_hash_hex, hashPartsDecimal);
    ProofNode** arrayOfPaths = (ProofNode**)malloc(HASH_LEN * sizeof(ProofNode*));

    unsigned char* secret_key_hash[NUM_HASHES];
    for (int i = 0; i < NUM_HASHES; i++) {
        // Generate proof path for the selected secret key
        arrayOfPaths[i] = generate_proof_path_with_direction(merkel_tree, levels, hashPartsDecimal[i], &path_length);

        secret_key_hash[i] = (unsigned char*)malloc(HASH_LEN * 2 + 1);
        // Convert secret key from hex to binary
        unsigned char secret_key_binary[HASH_LEN];
        hex_string_to_binary(secret_keys[hashPartsDecimal[i]], secret_key_binary, HASH_LEN);
        memcpy(secret_key_hash[i], secret_key_binary, (HASH_LEN * 2 + 1));
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("proof path generation took %f milli seconds to execute \n", cpu_time_used*1000);
    size_t proofPathArraySize = calculate_proof_path_array_size(arrayOfPaths, NUM_HASHES, path_length);
    printf("signature total size: %lu  bytes\n", (proofPathArraySize + sizeof(secret_key_hash)));
    printf("secret_key_hash size: %lu bytes\n", sizeof(secret_key_hash));
    printf("Printing secret_key_hash Array:\n");
    for (int i = 0; i < NUM_HASHES; i++) {
        printf("Secret: %s\n", secret_key_hash[i]);
    }
    printf("\nPrinting arrayOfPaths:\n");
    for (int i = 0; i < NUM_HASHES; i++) {
        if (arrayOfPaths[i] != NULL) { // Check if there's a path
            printf("Path for hash part %d:\n", i);
            for (int j = 0; j < path_length; j++) { // Assuming path_length is the length for all paths or adjust accordingly
                printf("Proof Node %d: Direction: %d, Hash: ", j, arrayOfPaths[i][j].direction);
                for (int k = 0; k < HASH_LEN; k++) {
                    printf("%02x", arrayOfPaths[i][j].hash[k]);
                }
                printf("\n");
            }
        }
    }

    start = clock();
    // Now verify the signature
    int signature_valid = verify_signature(hashPartsDecimal, arrayOfPaths, path_length, merkle_root, secret_key_hash);
    printf("Signature is %s\n", signature_valid ? "valid" : "invalid");
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Signature Verify took %f milli seconds to execute \n", cpu_time_used*1000);

    struct task_basic_info t_info;
    mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

    if (KERN_SUCCESS != task_info(mach_task_self(),
                                TASK_BASIC_INFO, (task_info_t)&t_info,
                                &t_info_count))
    {
        return -1;
    }
    printf("Memory used: %lu bytes (%.2f MB)\n", t_info.resident_size, t_info.resident_size / 1024.0 / 1024.0);


    return 0;
}