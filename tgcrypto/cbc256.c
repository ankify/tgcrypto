/*
 * Pyrogram - Telegram MTProto API Client Library for Python
 * Copyright (C) 2017-present Dan <https://github.com/delivrance>
 *
 * This file is part of Pyrogram.
 *
 * Pyrogram is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pyrogram is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.
 */

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
