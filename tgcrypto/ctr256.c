#include "aes256.h"
#include <stdlib.h>
#include <string.h>

uint8_t *ctr256(const uint8_t in[], uint32_t length, const uint8_t key[32], uint8_t iv[16], uint8_t *state) {
    if (!in || !key || !iv || !state) return NULL;

    uint8_t *out = (uint8_t *) malloc(length);
    if (!out) return NULL;

    uint8_t chunk[AES_BLOCK_SIZE];
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
    uint32_t i, j;

    memcpy(out, in, length);
    aes256_set_encryption_key(key, expandedKey);
    aes256_encrypt(iv, chunk, expandedKey);

    for (i = 0; i < length; i += AES_BLOCK_SIZE) {
        uint32_t blockSize = length - i < AES_BLOCK_SIZE ? length - i : AES_BLOCK_SIZE;

        for (j = 0; j < blockSize; ++j) {
            out[i + j] ^= chunk[*state];
            (*state)++;

            if (*state == AES_BLOCK_SIZE) {
                *state = 0;

                for (int k = AES_BLOCK_SIZE - 1; k >= 0; --k) {
                    if (++iv[k]) break;
                }

                aes256_encrypt(iv, chunk, expandedKey);
            }
        }
    }

    return out;
}
