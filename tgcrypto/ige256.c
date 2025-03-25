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

uint8_t *ige256(const uint8_t in[], uint32_t length, const uint8_t key[32], const uint8_t iv[32], uint8_t encrypt) {
    if (length == 0 || length % AES_BLOCK_SIZE != 0) {
        return NULL;
    }

    uint8_t *out = (uint8_t *)malloc(length);
    if (!out) {
        return NULL;
    }

    uint8_t iv1[AES_BLOCK_SIZE], iv2[AES_BLOCK_SIZE];
    uint8_t chunk[AES_BLOCK_SIZE] = {0};
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

    return out;
}
