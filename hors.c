#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "hash.h"
#include "hors.h"
#include "hash_address.h"
#include "params.h"
#include <unistd.h>


/**
 * HORS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full HORS private key and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this HORS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void gen_hors(const xmss_params *params,
                const unsigned char *pk, const unsigned char *sk,
                const unsigned char *pub_seed, uint32_t addr[9])
{
    uint32_t i;

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        hors_hash(params, pk, sk, params->padding_len + params->n + 32);
    }
}

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void hors_sign(const xmss_params *params,
               unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[9])
{
    uint32_t i;

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        hors_hash(params, pub_seed, seed, params->padding_len + params->n + 32);
    }
}

/**
 * Takes a HORS signature and an n-byte message, computes a HORS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void hors_pk_from_sig(const xmss_params *params, unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[9])
{
    uint32_t i;

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        hors_hash(params, pub_seed, pk, params->padding_len + params->n + 32);
    }
}
