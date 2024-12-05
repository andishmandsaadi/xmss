#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h> // For standard deviation calculation

#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"

#define XMSS_MLEN 32
#ifndef XMSS_SIGNATURES
    #define XMSS_SIGNATURES 500
    #define XMSS_VERIFIES 1141
    #define XMSS_KEYPAIRS 2
#endif

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
#endif

#ifndef XMSS_VARIANT
    #ifdef XMSSMT
        #define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
    #else
        #define XMSS_VARIANT "XMSS-SHA2_10_192"
    #endif
#endif

static unsigned long long cpucycles(void)
{
  unsigned long long result;
  __asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
    : "=a" (result) ::  "%rdx");
  return result;
}

static double stddev(unsigned long long *times, size_t len) {
    double mean = 0.0, sum = 0.0, stddev = 0.0;
    size_t i;
    for (i = 0; i < len; i++) {
        sum += times[i];
    }
    mean = sum / len;
    for (i = 0; i < len; i++) {
        stddev += pow(times[i] - mean, 2);
    }
    return sqrt(stddev / len);
}

static double stddev_time(double *times, size_t len) {
    double mean = 0.0, sum = 0.0, stddev = 0.0;
    size_t i;
    for (i = 0; i < len; i++) {
        sum += times[i];
    }
    mean = sum / len;
    for (i = 0; i < len; i++) {
        stddev += pow(times[i] - mean, 2);
    }
    return sqrt(stddev / len);
}

static double convert_to_us(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_nsec - start.tv_nsec) / 1e3;
}

static unsigned long long average(unsigned long long *arr, size_t len) {
    unsigned long long sum = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        sum += arr[i];
    }
    return sum / len;
}

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    xmss_params params;
    uint32_t oid;
    int ret = 0, i;

    // Parse OID
    if (XMSS_STR_TO_OID(&oid, XMSS_VARIANT)) {
        printf("XMSS variant %s not recognized!\n", XMSS_VARIANT);
        return -1;
    }
    XMSS_PARSE_OID(&params, oid);

    unsigned char hors_sk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *m = malloc(XMSS_MLEN);
    unsigned char *sm = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *mout = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned long long smlen, mlen;

    unsigned long long t0, t1;
    unsigned long long *t_keypair = malloc(sizeof(unsigned long long) * XMSS_KEYPAIRS);
    double *time_keypair = malloc(sizeof(double) * XMSS_KEYPAIRS); // Time in microseconds

    unsigned long long *t_sign = malloc(sizeof(unsigned long long) * XMSS_SIGNATURES);
    double *time_sign = malloc(sizeof(double) * XMSS_SIGNATURES); // Time in microseconds

    unsigned long long *t_verify = malloc(sizeof(unsigned long long) * XMSS_VERIFIES);
    double *time_verify = malloc(sizeof(double) * XMSS_VERIFIES); // Time in microseconds


    struct timespec start, stop;
    double total_time_keypair = 0.0, total_time_sign = 0.0, total_time_verify = 0.0;

    randombytes(m, XMSS_MLEN);

    printf("Benchmarking variant %s\n", XMSS_VARIANT);

    // Keypair generation (looped XMSS_KEYPAIRS times)
    for (i = 0; i < XMSS_KEYPAIRS; i++) {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        t0 = cpucycles();
        XMSS_KEYPAIR(hors_sk, pk, sk, oid);
        t1 = cpucycles();
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

        t_keypair[i] = t1 - t0;
        total_time_keypair += convert_to_us(start, stop);
        time_keypair[i] = convert_to_us(start, stop);
    }

    // Signature generation
    for (i = 0; i < XMSS_SIGNATURES; i++) {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        t0 = cpucycles();
        XMSS_SIGN(hors_sk, sk, sm, &smlen, m, XMSS_MLEN);
        t1 = cpucycles();
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

        t_sign[i] = t1 - t0;
        total_time_sign += convert_to_us(start, stop);
        time_sign[i] = convert_to_us(start, stop);
    }

    // Signature verification
    for (i = 0; i < XMSS_VERIFIES; i++) {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        t0 = cpucycles();
        ret |= XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk);
        t1 = cpucycles();
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

        t_verify[i] = t1 - t0;
        total_time_verify += convert_to_us(start, stop);
        time_verify[i] = convert_to_us(start, stop);
    }

    // Print Results
    printf("Iterations\tTotal Time (s)\tTime (us)\tStddev\tCPU Cycles (mean)\tCPU Cycles (stdev)\n");

    // Keypair
    printf("Keypair\t%d\t%.6f\t%.6f\t%.6f\t%llu\t%.6f\n",
        XMSS_KEYPAIRS,
        total_time_keypair / 1e6,
        total_time_keypair / XMSS_KEYPAIRS,
        stddev_time(time_keypair, XMSS_KEYPAIRS),
        average(t_keypair, XMSS_KEYPAIRS),
        stddev(t_keypair, XMSS_KEYPAIRS));

    // Sign
    printf("Sign\t%d\t%.6f\t%.6f\t%.6f\t%llu\t%.6f\n",
        XMSS_SIGNATURES,
        total_time_sign / 1e6,
        total_time_sign / XMSS_SIGNATURES,
        stddev_time(time_sign, XMSS_SIGNATURES),
        average(t_sign, XMSS_SIGNATURES),
        stddev(t_sign, XMSS_SIGNATURES));

    // Verify
    printf("Verify\t%d\t%.6f\t%.6f\t%.6f\t%llu\t%.6f\n",
        XMSS_VERIFIES,
        total_time_verify / 1e6,
        total_time_verify / XMSS_VERIFIES,
        stddev_time(time_verify, XMSS_VERIFIES),
        average(t_verify, XMSS_VERIFIES),
        stddev(t_verify, XMSS_VERIFIES));

    // Clean up
    free(m);
    free(sm);
    free(mout);
    free(t_keypair);
    free(t_sign);
    free(t_verify);

    return ret;
}
