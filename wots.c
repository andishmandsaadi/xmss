#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <mach/mach.h>

#define WOTS_N 32 // Length of hash output (SHA-256)
#define WOTS_W 16 // Winternitz parameter
#define WOTS_L ((256 + WOTS_W - 1) / WOTS_W) // Number of chains

clock_t start, end;
double cpu_time_used;

void wots_hash(unsigned char *out, const unsigned char *in, size_t len) {
    SHA256(in, len, out);
}

void wots_gen_chain(unsigned char *out, const unsigned char *seed, unsigned int chainlen) {
    memcpy(out, seed, WOTS_N);
    for (unsigned int i = 0; i < chainlen; ++i) {
        wots_hash(out, out, WOTS_N);
    }
}

void wots_gen_keypair(unsigned char public_key[WOTS_L][WOTS_N], unsigned char private_key[WOTS_L][WOTS_N]) {
    for (int i = 0; i < WOTS_L; ++i) {
        // In a real implementation, this should be a cryptographic random number
        for (int j = 0; j < WOTS_N; ++j) {
            private_key[i][j] = rand() % 256;
        }
        wots_gen_chain(public_key[i], private_key[i], WOTS_W - 1);
    }
}

void wots_sign(unsigned char signature[WOTS_L][WOTS_N], const unsigned char *message, const unsigned char private_key[WOTS_L][WOTS_N]) {
    unsigned char hash[WOTS_N];
    wots_hash(hash, message, strlen((char *)message));

    for (int i = 0; i < WOTS_L; ++i) {
        unsigned int chainlen = (hash[i / 2] >> (4 * (i % 2))) & (WOTS_W - 1);
        wots_gen_chain(signature[i], private_key[i], chainlen);
    }
}

int wots_verify(const unsigned char signature[WOTS_L][WOTS_N], const unsigned char *message, const unsigned char public_key[WOTS_L][WOTS_N]) {
    unsigned char hash[WOTS_N];
    wots_hash(hash, message, strlen((char *)message));

    unsigned char verify[WOTS_N];
    for (int i = 0; i < WOTS_L; ++i) {
        unsigned int chainlen = WOTS_W - 1 - ((hash[i / 2] >> (4 * (i % 2))) & (WOTS_W - 1));
        wots_gen_chain(verify, signature[i], chainlen);
        if (memcmp(verify, public_key[i], WOTS_N) != 0) {
            return 0; // Verification failed
        }
    }
    return 1; // Verification succeeded
}

int main() {
    printf("SHA256\n");
    start = clock();
    unsigned char public_key[WOTS_L][WOTS_N];
    unsigned char private_key[WOTS_L][WOTS_N];
    unsigned char signature[WOTS_L][WOTS_N];

    wots_gen_keypair(public_key, private_key);
    end = clock();

    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Key generation took %f seconds to execute \n", cpu_time_used);
    printf("Key size: %lu bytes\n", sizeof(private_key)); // For private or public key size

    start = clock();
    char *message = "Test message";
    wots_sign(signature, (unsigned char *)message, private_key);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Signature took %f seconds to execute \n", cpu_time_used);
    printf("Signature size: %lu bytes\n", sizeof(signature));

    start = clock();
    int valid = wots_verify(signature, (unsigned char *)message, public_key);
    printf("Signature is %s\n", valid ? "valid" : "invalid");
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
