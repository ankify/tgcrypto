#pragma once

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t *cbc256(const uint8_t *restrict in, size_t length, const uint8_t key[32], uint8_t iv[16], uint8_t encrypt);

#ifdef __cplusplus
}
#endif
