#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <math.h>
#include <time.h>

#define WOTS_N 32  // Using SHA-256, so N is 32 bytes
#define WOTS_W 16  // Winternitz parameter
#define WOTS_L1 ((int)(256 / log2(WOTS_W)))  // Number of message blocks
#define WOTS_L2 ((int)ceil(log2(WOTS_L1 * (WOTS_W - 1)) / log2(WOTS_W)))  // Number of checksum blocks
#define WOTS_L (WOTS_L1 + WOTS_L2)  // Total number of blocks

clock_t start, end;
double cpu_time_used;

void secure_zero(void *p, size_t n) {
    volatile unsigned char *vp = p;
    while (n--) *vp++ = 0;
}

// Hash function wrapper
void wots_hash(unsigned char *out, const unsigned char *in, size_t len) {
    SHA256(in, len, out);
}

void chain(unsigned char *out, const unsigned char *in, int start, int steps, const unsigned char *bitmask) {
    memcpy(out, in, WOTS_N);
    for (int i = start; i < steps; ++i) {
        for (int j = 0; j < WOTS_N; ++j) {
            out[j] ^= bitmask[j];
        }
        wots_hash(out, out, WOTS_N);
    }
}

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

// Secure RNG for keys
void wots_gen_key(unsigned char public_key[WOTS_L][WOTS_N], unsigned char private_key[WOTS_L][WOTS_N], const unsigned char *bitmask) {
    for (int i = 0; i < WOTS_L; ++i) {
        if (1 != RAND_bytes(private_key[i], WOTS_N)) {
            fprintf(stderr, "Error generating random bytes.\n");
            exit(1);  // Handle errors appropriately in production code
        }
        chain(public_key[i], private_key[i], 0, WOTS_W - 1, bitmask);
    }
}

// Signature generation with size parameter for private_key
void wots_sign(unsigned char signature[WOTS_L][WOTS_N], const unsigned char *message,
               const unsigned char private_key[WOTS_L][WOTS_N], const unsigned char *bitmask, size_t pk_size) {
    unsigned char hash[WOTS_N];
    unsigned int base_w_msg[WOTS_L1];
    wots_hash(hash, message, strlen((char *)message));
    to_base_w(base_w_msg, hash, WOTS_L1);

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
    secure_zero((void *)private_key, pk_size);
}


int wots_verify(const unsigned char signature[WOTS_L][WOTS_N], const unsigned char *message, const unsigned char public_key[WOTS_L][WOTS_N], const unsigned char *bitmask) {
    unsigned char hash[WOTS_N];
    unsigned int base_w_msg[WOTS_L1];
    wots_hash(hash, message, strlen((char *)message));
    to_base_w(base_w_msg, hash, WOTS_L1);

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

int main() {
    printf("SHA256\n");
    printf("l %d \n",WOTS_L);
    start = clock();
    unsigned char public_key[WOTS_L][WOTS_N];
    unsigned char private_key[WOTS_L][WOTS_N];
    unsigned char signature[WOTS_L][WOTS_N];
    unsigned char bitmask[WOTS_N] = {0};  // In a real implementation, this should be a cryptographic random value

    if (1 != RAND_bytes(bitmask, WOTS_N)) {
        fprintf(stderr, "Error generating random bytes for bitmask.\n");
        exit(1);
    }

    wots_gen_key(public_key, private_key, bitmask);
    end = clock();

    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Key generation took %f seconds to execute \n", cpu_time_used);
    printf("Key size: %lu bytes\n", sizeof(private_key)); // For private or public key size

    start = clock();
    size_t private_key_size = sizeof(private_key);
    wots_gen_key(public_key, private_key, bitmask);
    const char *message = "Test message";
    wots_sign(signature, (unsigned char *)message, private_key, bitmask, private_key_size);

    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Signature took %f seconds to execute \n", cpu_time_used);
    printf("Signature size: %lu bytes\n", sizeof(signature));

    start = clock();
    int valid = wots_verify(signature, (unsigned char *)message, public_key, bitmask);
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
