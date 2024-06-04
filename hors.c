#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <mach/mach.h>

#define KEY_SIZE 1
#define HASH_LEN 32

clock_t start, end;
double cpu_time_used;

// Generates a random private key
void generate_private_key(unsigned char *private_key) {
    RAND_bytes(private_key, HASH_LEN);
}

void hash256(const unsigned char *input, size_t len, unsigned char output[HASH_LEN]) {
    SHA256(input, len, output);
}

// Computes the SHA-256 hash of the private key to generate the public key
void generate_public_key(unsigned char *private_key, unsigned char *public_key) {
    hash256(private_key, HASH_LEN, public_key);
}

// Signs a message using a private key selected based on the hash of the message
void sign(unsigned char private_keys[][HASH_LEN], unsigned char *message, size_t message_len, unsigned char *signature, int *key_index) {
    unsigned char message_hash[HASH_LEN];

    hash256(message, HASH_LEN, message_hash);

    // Simplified selection of a single key based on the first byte of the hash
    *key_index = message_hash[0] % KEY_SIZE;
    memcpy(signature, private_keys[*key_index], HASH_LEN);
}

// Verifies the signature of a message
int verify(unsigned char public_keys[][HASH_LEN], unsigned char *message, size_t message_len, unsigned char *signature, int key_index) {
    unsigned char message_hash[HASH_LEN];
    unsigned char expected_public_key[HASH_LEN];

    // Hash the message
    hash256(message, HASH_LEN, message_hash);

    // Compute expected public key from the signature
    hash256(signature, HASH_LEN, expected_public_key);

    // Compare the expected public key with the actual public key
    return memcmp(expected_public_key, public_keys[key_index], HASH_LEN) == 0;
}

int main() {
    printf("SHA256\n");
    start = clock();
    unsigned char private_keys[KEY_SIZE][HASH_LEN];
    unsigned char public_keys[KEY_SIZE][HASH_LEN];
    unsigned char signature[HASH_LEN];
    int key_index;

    // Generate key pairs
    for (int i = 0; i < KEY_SIZE; i++) {
        generate_private_key(private_keys[i]);
        generate_public_key(private_keys[i], public_keys[i]);
    }
    end = clock();

    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Key generation took %f seconds to execute \n", cpu_time_used);
    printf("Key size: %lu bytes\n", sizeof(private_keys)); // For private or public key size

    // Example message
    unsigned char message[] = "Hello, World!";
    size_t message_len = strlen((char *)message);

    // Sign the message
    start = clock();
    sign(private_keys, message, message_len, signature, &key_index);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Signature took %f seconds to execute \n", cpu_time_used);
    printf("Signature size: %lu bytes\n", sizeof(signature));

    // Verify the signature
    start = clock();
    if (verify(public_keys, message, message_len, signature, key_index)) {
        printf("Signature verified successfully.\n");
    } else {
        printf("Signature verification failed.\n");
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Signature Verify took %f seconds to execute \n", cpu_time_used);

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
