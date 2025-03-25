#include "aes256.h"
#include <stdio.h>

uint8_t *cbc256(const uint8_t *restrict in, uint32_t length, const uint8_t key[32], uint8_t iv[16], uint8_t encrypt) {
    if (length % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Input length must be a multiple of %d bytes.\n", AES_BLOCK_SIZE);
        return NULL;
    }

    uint8_t *out = (uint8_t *)malloc(length);
    if (!out) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        return NULL;
    }

    uint8_t nextIv[AES_BLOCK_SIZE];
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
    uint32_t i, j;

    if (encrypt) {
        aes256_set_encryption_key(key, expandedKey);

        for (i = 0; i < length; i += AES_BLOCK_SIZE) {
            for (j = 0; j < AES_BLOCK_SIZE; ++j)
                out[i + j] = in[i + j] ^ iv[j];

            aes256_encrypt(&out[i], &out[i], expandedKey);
            memcpy(iv, &out[i], AES_BLOCK_SIZE);
        }
    } else {
        aes256_set_decryption_key(key, expandedKey);

        for (i = 0; i < length; i += AES_BLOCK_SIZE) {
            memcpy(nextIv, &in[i], AES_BLOCK_SIZE);
            aes256_decrypt(&in[i], &out[i], expandedKey);

            for (j = 0; j < AES_BLOCK_SIZE; ++j)
                out[i + j] ^= iv[j];

            memcpy(iv, nextIv, AES_BLOCK_SIZE);
        }
    }

    return out;
}
