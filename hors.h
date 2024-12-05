#ifndef XMSS_HORS_H
#define XMSS_HORS_H

#include <stdint.h>
#include "params.h"
#include <mach/mach.h>
#define HASH_LEN 32

// Generates a random private key
void gen_hors(const xmss_params *params,
                const unsigned char *pk, const unsigned char *sk,
                const unsigned char *pub_seed, uint32_t addr[9]);

// Signs a message using a private key selected based on the hash of the message
void hors_sign(const xmss_params *params,
               unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[9]);
// verify
void hors_pk_from_sig(const xmss_params *params, unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[9]);

#endif
