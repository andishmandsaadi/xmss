#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <mach/mach.h>
#include <math.h>
#include <time.h>
#include <openssl/hmac.h>

#define WOTS_N 32
#define WOTS_W 16
#define WOTS_L1 (256 / 4)
#define WOTS_L2 3
#define WOTS_L (WOTS_L1 + WOTS_L2)

#define TEST_SIGNATURES 16
#define NUM_SECRET_KEYS 1048576
#define HASH_LEN WOTS_N


// Function to generate a SHA-256 hash
void hash256(const unsigned char *data, size_t data_len, unsigned char *out) {
    SHA256(data, data_len, out);
}

// Function to apply the chain operation using HMAC-SHA-256
void chain(unsigned char *out, int start, int steps, unsigned char *bitmask, size_t bitmask_len) {
    unsigned char new_val[WOTS_N];
    unsigned char tohash[WOTS_N];
    for (int i = start; i < steps; i++) {
        HMAC(EVP_SHA256(), bitmask, bitmask_len, out, WOTS_N, new_val, NULL);
        // Perform XOR between `out` and `new_val`
        for (int j = 0; j < WOTS_N; j++) {
            tohash[j] = out[j] ^ new_val[j];
        }
        // Apply the WOTS hash function on `tohash`
        hash256(tohash ,sizeof(tohash) , out);
    }
}

// Generate the WOTS+ keys
void wots_gen_key(unsigned char private_key[][WOTS_N], unsigned char public_key[][WOTS_N], unsigned char *bitmask, size_t bitmask_len) {
    for (int i = 0; i < WOTS_L; i++) {
        RAND_bytes(private_key[i], WOTS_N);

        memcpy(public_key[i], private_key[i], WOTS_N);
        chain(public_key[i], 0, WOTS_W - 1, bitmask, bitmask_len);

    }
}

int checksumCalculate(int *values, size_t len) {
    int result = 0;
    for (size_t i = 0; i < len; i++) {
        result += WOTS_W - 1 - values[i];
    }
    return result;
}

// Convert byte array to hexadecimal string
void bytes_to_hex_string(const unsigned char *bytes, size_t len, char *hex_string) {
    for (size_t i = 0; i < len; i++) {
        sprintf(&hex_string[i * 2], "%02x", bytes[i]);
    }
}

void hex_string_to_int_array(const char *hex_string, int *int_array) {
    size_t len = strlen(hex_string);
    for (size_t i = 0; i < len; i++) {
        char ch = hex_string[i];
        if (ch >= '0' && ch <= '9') {
            int_array[i] = ch - '0';
        } else if (ch >= 'a' && ch <= 'f') {
            int_array[i] = 10 + (ch - 'a');
        } else if (ch >= 'A' && ch <= 'F') {
            int_array[i] = 10 + (ch - 'A');
        }
    }
}

void appendBaseConversion(int num, int base, int *digits, int start_index) {
    int temp[64]; // Large enough temporary array to hold digits in reverse order
    int index = 0;

    do {
        temp[index++] = num % base;
        num /= base;
    } while (num > 0);

    // Reverse the order of digits into the correct position in the original array
    for (int i = 0; i < index; i++) {
        digits[start_index + i] = temp[index - 1 - i];
    }
}

int *to_base_w(unsigned char *value, size_t value_len) {
    char hex_string[2 * value_len + 1];
    bytes_to_hex_string(value, value_len, hex_string);
    hex_string[2 * value_len] = '\0'; // Null-terminate the string


    // Allocate memory dynamically for bit_values
    int *bit_values = malloc((WOTS_L1 + WOTS_L2) * sizeof(int));
    if (bit_values == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL; // Return NULL if memory allocation fails
    }

    hex_string_to_int_array(hex_string, bit_values);

    int checksum = checksumCalculate(bit_values, WOTS_L1);

    // Append the base 16 representation of the checksum to bit_values
    appendBaseConversion(checksum, 16, bit_values, WOTS_L1);

    return bit_values;
}

// Sign a message
void wots_sign(unsigned char signature[][WOTS_N], unsigned char *message, size_t message_len, unsigned char private_key[][WOTS_N], unsigned char *bitmask, size_t bitmask_len) {
    unsigned char hash[WOTS_N];
    hash256(message, message_len, hash);

    int *base_w_msg = to_base_w(hash, WOTS_N);
    // Placeholder for conversion to base W and checksum
    for (int i = 0; i < WOTS_L; i++) {
        memcpy(signature[i], private_key[i], WOTS_N);
        chain(signature[i], 0,base_w_msg[i], bitmask, bitmask_len);
    }
}

// Verify a signature
int wots_verify(unsigned char signature[][WOTS_N], unsigned char *message, size_t message_len, unsigned char public_key[][WOTS_N], unsigned char *bitmask, size_t bitmask_len) {
    unsigned char hash[WOTS_N];
    hash256(message, message_len, hash);

    int *base_w_msg = to_base_w(hash, WOTS_N);

    // Placeholder for conversion to base W and checksum
    for (int i = 0; i < WOTS_L; i++) {
        unsigned char temp[WOTS_N];
        memcpy(temp, signature[i], WOTS_N);
        chain(temp, 0, WOTS_W - 1 -base_w_msg[i], bitmask, bitmask_len);

        if (memcmp(temp, public_key[i], WOTS_N) != 0) {
            return 0; // False
        }
    }
    return 1; // True
}

void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex_output) {
    for(size_t i = 0; i < len; i++) {
        snprintf(hex_output + (i * 2), 3, "%02x", bytes[i]);
    }
    hex_output[len * 2] = '\0'; // Null-terminate the string
}


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
        snprintf(output + (i * 2), 3, "%02x", hash[i]);
    }
    output[len * 2] = '\0'; // Null-terminate string
}



typedef struct {
    unsigned char public_key[WOTS_L][WOTS_N];
    unsigned char private_key[WOTS_L][WOTS_N];
} WOTS_KeyPair;

typedef struct {
    // Structure to hold the XMSS Merkle tree.
    // The specifics of this structure depend on how you implement the tree.
    // array of node levels,
    // with each level being an array of hashes.
    unsigned char** levels;
    int num_levels;
} XMSS_Tree;

WOTS_KeyPair* generate_wots_keys(int number_of_keys, unsigned char *bitmask) {
    WOTS_KeyPair* wots_keys = malloc(number_of_keys * sizeof(WOTS_KeyPair));
    if (!wots_keys) {
        fprintf(stderr, "Failed to allocate memory for WOTS keys.\n");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < number_of_keys; i++) {
        wots_gen_key(wots_keys[i].private_key, wots_keys[i].public_key, bitmask, sizeof(bitmask));
    }
    return wots_keys;
}

void l_tree(unsigned char public_key[WOTS_L][WOTS_N], unsigned char *l_tree_root, const unsigned char *bitmask) {
    int num_nodes = WOTS_L;
    unsigned char nodes[WOTS_L][WOTS_N];

    // Copy initial nodes
    for (int i = 0; i < num_nodes; i++) {
        memcpy(nodes[i], public_key[i], WOTS_N);
    }

    while (num_nodes > 1) {
        for (int i = 0; i < num_nodes / 2; i++) {
            // Hash pairs of nodes together
            unsigned char temp[WOTS_N * 2];
            memcpy(temp, nodes[i * 2], WOTS_N);
            memcpy(temp + WOTS_N, nodes[i * 2 + 1], WOTS_N);
            for (int j = 0; j < WOTS_N * 2; j++) {
                temp[j] ^= bitmask[j % WOTS_N];
            }
            hash256(temp, WOTS_N * 2, nodes[i]);
        }
        if (num_nodes % 2 == 1) {
            memcpy(nodes[num_nodes / 2], nodes[num_nodes - 1], WOTS_N);
            num_nodes = num_nodes / 2 + 1;
        } else {
            num_nodes /= 2;
        }
    }
    memcpy(l_tree_root, nodes[0], WOTS_N);
}

unsigned char*** build_merkle_tree(char **secret_keys, int leavesCount) {
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
            hashArray[i][j] = malloc(HASH_LEN);
        }
    }

    // Initialize leaf level with secret keys
    for (int j = 0; j < leavesCount; j++) {
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

unsigned char*** build_xmss_tree(WOTS_KeyPair* wots_keys, int number_of_keys, const unsigned char *bitmask) {
    unsigned char l_tree_root[WOTS_N];
    char **hex_l_tree_roots = malloc(number_of_keys * sizeof(char *));
    if (hex_l_tree_roots == NULL) {
        fprintf(stderr, "Failed to allocate memory for hex_l_tree_roots.\n");
        return NULL;
    }

    for (int i = 0; i < number_of_keys; i++) {
        hex_l_tree_roots[i] = malloc((HASH_LEN * 2 + 1) * sizeof(char));
        l_tree(wots_keys[i].public_key, l_tree_root, bitmask); // Generate binary L-Tree root
        bytes_to_hex(l_tree_root, WOTS_N, hex_l_tree_roots[i]); // Convert to hexadecimal string
    }

    unsigned char ***merkle_tree = build_merkle_tree(hex_l_tree_roots, number_of_keys);

    for (int i = 0; i < number_of_keys; i++) {
        free(hex_l_tree_roots[i]);
    }
    free(hex_l_tree_roots);

    return merkle_tree;
}



// struct to hold a node in the path and its direction
typedef struct {
    unsigned char* hash; // Sibling hash
    int direction; // 0 for left, 1 for right
} ProofNode;

typedef struct {
    // WOTS+ signature
    unsigned char wots_signature[WOTS_L][WOTS_N];
    // Authentication path (simplified)
        ProofNode* authentication_path;
    // Index of the leaf in the Merkle tree
    int leaf_index;
    int path_length;
} XMSS_Signature;

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


// Sign a message with XMSS
XMSS_Signature xmss_sign(unsigned char *message, WOTS_KeyPair *wots_keys, unsigned char ***xmss_tree, int number_of_keys, unsigned char *bitmask) {
    XMSS_Signature xmss_signature;
    // Calculate total levels in the XMSS tree
    int levels = 1;
    int temp = number_of_keys;
    while (temp > 1) {
        temp = (temp + 1) / 2;
        levels++;
    }
    int path_length = 0;

    // Step 1: Sign the message using the selected WOTS+ private key
    unsigned char message_hash[HASH_LEN];
    hash256((unsigned char *)message, strlen((char *)message), message_hash);

    // printf("Secret key size: %lu bytes \n", sizeof(wots_keys[leaf_index]));
    int leaf_index = message_hash[0] % NUM_SECRET_KEYS;

    size_t private_key_size = sizeof(wots_keys[leaf_index].private_key);

    // wots_sign(xmss_signature.wots_signature, message_hash, wots_keys[leaf_index].private_key, bitmask, private_key_size);
    wots_sign(xmss_signature.wots_signature, message, strlen((char *)message), wots_keys[leaf_index].private_key, bitmask, sizeof(bitmask));
    // Step 2: Generate prrof path
    xmss_signature.authentication_path = generate_proof_path_with_direction(xmss_tree, levels, leaf_index, &path_length);
    // Step 3: Set the leaf index and path length in the signature
    xmss_signature.path_length = path_length;
    xmss_signature.leaf_index = leaf_index;

    return xmss_signature;
}

// Verify the signature
int verify_signature(const unsigned char* message_hash, ProofNode* proof_path, int path_length, const unsigned char* merkle_root, const unsigned char* secret_key) {

    unsigned char current_hash[HASH_LEN];
    unsigned char concatenated[HASH_LEN * 2];
    // Use memcpy to copy secret_key into current_hash
    memcpy(current_hash, secret_key, HASH_LEN);
    for (int i = 0; i < path_length; ++i) {
        if (proof_path[i].direction == 0) { // If the direction is 0, current_hash is left sibling
            concatenate_and_hash(current_hash, proof_path[i].hash, concatenated);
        } else { // If the direction is 1, current_hash is right sibling
            concatenate_and_hash(proof_path[i].hash, current_hash, concatenated);
        }
        memcpy(current_hash, concatenated, HASH_LEN);
    }

    // Compare the computed hash with the provided merkle root
    return memcmp(current_hash, merkle_root, HASH_LEN) == 0;
}

// Verification of XMSS signature
int xmss_verify(unsigned char *message, WOTS_KeyPair *wots_keys, int number_of_keys, const unsigned char *root, XMSS_Signature *signature,  unsigned char *bitmask) {

    // Step 1: Recompute the WOTS+ public key from the signature and message
    unsigned char recompute_pubkey[WOTS_L][WOTS_N];
    if (!wots_verify(signature->wots_signature, message, strlen((char *)message), wots_keys[signature->leaf_index].public_key, bitmask, sizeof(bitmask))) {
        printf("WOTS+ verification failed.\n");
        return 0;
    }

    unsigned char message_hash[HASH_LEN];
    hash256((const unsigned char *)message, strlen((const char *)message), message_hash);
    unsigned char l_tree_root[WOTS_N];
    l_tree(wots_keys[signature->leaf_index].public_key, l_tree_root, bitmask);
    char l_tree_root_hex[HASH_LEN * 2 + 1];
    bytes_to_hex(l_tree_root, WOTS_N, l_tree_root_hex);

    unsigned char secret_key_binary[HASH_LEN];
    hex_string_to_binary(l_tree_root_hex, secret_key_binary, HASH_LEN);
    // Now verify the signature with correct parameters
    int signature_valid = verify_signature(message_hash, signature->authentication_path,  signature->path_length, root, secret_key_binary);
    if (signature_valid == 1) {
        // printf("XMSS verification successful.\n");
        return 1;
    } else {
        printf("XMSS verification failed.\n");
        return 0;
    }
}

static unsigned long long get_cpu_cycles(void)
{
    unsigned long long cycles;
    __asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
                   : "=a" (cycles) :: "%rdx");
    return cycles;
}

static int compare_uint64(const void *first, const void *second)
{
    unsigned long long val_a = *(unsigned long long *)first;
    unsigned long long val_b = *(unsigned long long *)second;

    return (val_a > val_b) - (val_a < val_b);
}

static unsigned long long calculate_median(unsigned long long *values, size_t count)
{
    qsort(values, count, sizeof(unsigned long long), compare_uint64);
    size_t mid = count / 2;

    return (count % 2 != 0) ? values[mid] : (values[mid - 1] + values[mid]) / 2;
}

static unsigned long long calculate_average(unsigned long long *array, size_t length)
{
    unsigned long long sum = 0;
    for (size_t idx = 0; idx < length; idx++) {
        sum += array[idx];
    }
    return sum / length;
}

static void display_results(unsigned long long *cycles_array, size_t length)
{
    // Compute the differences first
    for (size_t idx = 0; idx < length - 1; idx++) {
        cycles_array[idx] = cycles_array[idx + 1] - cycles_array[idx];
    }

    // Now display median and average
    printf("\tmedian cycles : %llu\n", calculate_median(cycles_array, length));
    printf("\taverage cycles: %llu\n", calculate_average(cycles_array, length - 1));
    printf("\n");
}


int main() {
    unsigned long long t0, t1;
    struct timespec start, stop;
    double result;
    unsigned long long *t = malloc(sizeof(unsigned long long) * TEST_SIGNATURES);
    printf("SHA256\n");
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    t0 = get_cpu_cycles();
    int number_of_keys = NUM_SECRET_KEYS;
    unsigned char bitmask[WOTS_N] = {0}; // This should be securely generated
    int levels = 1;
    int temp = number_of_keys;
    while (temp > 1) {
        temp = (temp + 1) / 2;
        levels++;
    }
    WOTS_KeyPair* wots_keys = generate_wots_keys(number_of_keys, bitmask);

    unsigned char*** xmss_tree = build_xmss_tree(wots_keys, number_of_keys,bitmask);

    t1 = get_cpu_cycles();
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
    result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
    printf("took %lf us (%.2lf sec), %llu cycles\n", result, result / 1e6, t1 - t0);

    // Sign and verify a message
    unsigned char *message = (unsigned char *)"My message in bytes format";
    int random_index;

    unsigned char* root = xmss_tree[levels - 1][0];
    XMSS_Signature signaturXmss[TEST_SIGNATURES];
    printf("Creating %d signatures..\n", TEST_SIGNATURES);
    for (int i = 0; i < TEST_SIGNATURES; i++) {
        // random_index = rand() % NUM_SECRET_KEYS;
        t[i] = get_cpu_cycles();
        signaturXmss[i] = xmss_sign(message, wots_keys, xmss_tree, number_of_keys, bitmask);
    }
    display_results(t, TEST_SIGNATURES);
    printf("Verifying %d signatures..\n", TEST_SIGNATURES);

    for (int i = 0; i < TEST_SIGNATURES; i++) {
        t[i] = get_cpu_cycles();
        int verification_result = xmss_verify(message,wots_keys, number_of_keys, root, &signaturXmss[i], bitmask);
        // printf("Verification result: %s\n", verification_result ? "PASS" : "FAIL");
    }
    display_results(t, TEST_SIGNATURES);


    char root_hex[HASH_LEN * 2 + 1];
    bytes_to_hex(root, WOTS_N, root_hex);
    printf("root %s \n", root_hex);
    printf("Public key size: %lu bytes \n", sizeof(root));

    printf("Signature size: %lu bytes \n", sizeof(signaturXmss[0]) + sizeof(root) + sizeof(wots_keys[signaturXmss[0].leaf_index].public_key) + sizeof(wots_keys[signaturXmss[0].leaf_index].private_key));
    printf("Signature size: %lu bytes \n", sizeof(signaturXmss[0]));

    // individual size:
    size_t size_of_one_secret_key = WOTS_L * WOTS_N;
    printf("Size of secret key: %zu bytes\n", size_of_one_secret_key);


    struct task_basic_info t_info;
    mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

    if (KERN_SUCCESS != task_info(mach_task_self(),
                                TASK_BASIC_INFO, (task_info_t)&t_info,
                                &t_info_count))
    {
        return -1;
    }
    // Free allocated memory for the XMSS tree
    for (int i = 0; i < levels; ++i) {
        int levelCount = (number_of_keys + (1 << i) - 1) / (1 << i);
        for (int j = 0; j < levelCount; ++j) {
            free(xmss_tree[i][j]);
        }
        free(xmss_tree[i]);
    }
    free(xmss_tree);

    return 0;
}

