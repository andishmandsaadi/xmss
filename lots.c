#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <mach/mach.h>

// Define the size of the hash output (SHA-256)
#define HASH_SIZE 64

clock_t start, end;
double cpu_time_used;

// Function to print hash in hexadecimal
void print_hash(unsigned char *hash) {
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// Function to print a key (public or private)
void print_key(unsigned char key[HASH_SIZE][2][HASH_SIZE]) {
    for (int i = 0; i < HASH_SIZE; i++) {
        for (int j = 0; j < 2; j++) {
            print_hash(key[i][j]);
        }
        printf("\n");
    }
}

// Function to generate a Lamport key pair
void generate_lamport_key_pair(unsigned char private_key[HASH_SIZE][2][HASH_SIZE],
                               unsigned char public_key[HASH_SIZE][2][HASH_SIZE]) {
    for (int i = 0; i < HASH_SIZE; i++) {
        for (int j = 0; j < 2; j++) {
            RAND_bytes(private_key[i][j], HASH_SIZE);
            SHA512(private_key[i][j], HASH_SIZE, public_key[i][j]);
        }
    }
}

// Function to create a signature
void sign_message(unsigned char *message,
                  unsigned char private_key[HASH_SIZE][2][HASH_SIZE],
                  unsigned char signature[HASH_SIZE][HASH_SIZE]) {
    unsigned char hash[HASH_SIZE];
    SHA512(message, strlen((char *)message), hash);

    for (int i = 0; i < HASH_SIZE; i++) {
        int bit = (hash[i / 8] >> (7 - i % 8)) & 1;
        memcpy(signature[i], private_key[i][bit], HASH_SIZE);
    }
}

// Function to verify a signature
int verify_signature(unsigned char *message,
                     unsigned char signature[HASH_SIZE][HASH_SIZE],
                     unsigned char public_key[HASH_SIZE][2][HASH_SIZE]) {
    unsigned char hash[HASH_SIZE];
    SHA512(message, strlen((char *)message), hash);

    for (int i = 0; i < HASH_SIZE; i++) {
        int bit = (hash[i / 8] >> (7 - i % 8)) & 1;
        unsigned char computed_hash[HASH_SIZE];
        SHA512(signature[i], HASH_SIZE, computed_hash);

        if (memcmp(computed_hash, public_key[i][bit], HASH_SIZE) != 0) {
            return 0;  // Signature is invalid
        }
    }
    return 1;  // Signature is valid
}

int main() {
    printf("SHA512\n");
    start = clock();
    unsigned char private_key[HASH_SIZE][2][HASH_SIZE];
    unsigned char public_key[HASH_SIZE][2][HASH_SIZE];
    unsigned char signature[HASH_SIZE][HASH_SIZE];

    // Generate key pair
    generate_lamport_key_pair(private_key, public_key);
    end = clock();

    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Key generation took %f seconds to execute \n", cpu_time_used);
    printf("Key size: %lu bytes\n", sizeof(private_key)); // For private or public key size

    // printf("Private Key:\n");
    // print_key(private_key);

    // printf("Public Key:\n");
    // print_key(public_key);

    // Message to be signed
    unsigned char message[] = "Hello, world!";
    // printf("Message: %s\n", message);

    // Sign the message
    start = clock();
    sign_message(message, private_key, signature);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Signature took %f seconds to execute \n", cpu_time_used);
    printf("Signature size: %lu bytes\n", sizeof(signature));

    // printf("Signature:\n");
    // for (int i = 0; i < HASH_SIZE; i++) {
    //     print_hash(signature[i]);
    // }

    start = clock();
    // Verify the signature
    int valid = verify_signature(message, signature, public_key);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Signature Verify took %f seconds to execute \n", cpu_time_used);
    printf("Signature is %s\n", valid ? "valid" : "invalid");
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
