#include "aes256.h"

uint8_t *ige256(const uint8_t in[], uint32_t length, const uint8_t key[32], const uint8_t iv[32], uint8_t encrypt) {
    if (length == 0 || length % AES_BLOCK_SIZE != 0) {
        return NULL;  // Ensure valid block size
    }

    uint8_t *out = (uint8_t *)malloc(length);
    if (!out) {
        return NULL;  // Prevents memory allocation failure
    }

    uint8_t iv1[AES_BLOCK_SIZE], iv2[AES_BLOCK_SIZE];
    uint8_t chunk[AES_BLOCK_SIZE] = {0};  // Ensure zero-initialized for incomplete blocks
    uint8_t buffer[AES_BLOCK_SIZE];
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
    uint32_t i, j;

    memcpy(encrypt ? iv1 : iv2, iv, AES_BLOCK_SIZE);
    memcpy(encrypt ? iv2 : iv1, iv + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    
    if (encrypt) {
        aes256_set_encryption_key(key, expandedKey);
    } else {
        aes256_set_decryption_key(key, expandedKey);
    }

    for (i = 0; i < length; i += AES_BLOCK_SIZE) {
        memset(chunk, 0, AES_BLOCK_SIZE);
        memcpy(chunk, &in[i], (length - i < AES_BLOCK_SIZE) ? (length - i) : AES_BLOCK_SIZE);

        for (j = 0; j < AES_BLOCK_SIZE; ++j) {
            buffer[j] = chunk[j] ^ iv1[j];
        }

        if (encrypt) {
            aes256_encrypt(buffer, &out[i], expandedKey);
        } else {
            aes256_decrypt(buffer, &out[i], expandedKey);
        }

        for (j = 0; j < AES_BLOCK_SIZE; ++j) {
            out[i + j] ^= iv2[j];
        }

        memcpy(iv1, &out[i], AES_BLOCK_SIZE);
        memcpy(iv2, chunk, AES_BLOCK_SIZE);
    }

    // Caller must free(out) after use
    return out;
}
