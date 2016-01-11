/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _BVB_SHA_H
#define _BVB_SHA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bvb_sysdeps.h"

#define BVB_SHA256_DIGEST_SIZE 32
#define BVB_SHA256_BLOCK_SIZE 64

#define BVB_SHA512_DIGEST_SIZE 64
#define BVB_SHA512_BLOCK_SIZE 128

typedef struct {
  uint32_t h[8];
  uint32_t tot_len;
  uint32_t len;
  uint8_t block[2 * BVB_SHA256_BLOCK_SIZE];
  uint8_t buf[BVB_SHA256_DIGEST_SIZE];  /* Used for storing the final digest. */
} BvbSHA256Ctx;

typedef struct {
  uint64_t h[8];
  uint32_t tot_len;
  uint32_t len;
  uint8_t block[2 * BVB_SHA512_BLOCK_SIZE];
  uint8_t buf[BVB_SHA512_DIGEST_SIZE];  /* Used for storing the final digest. */
} BvbSHA512Ctx;

void bvb_SHA256_init(BvbSHA256Ctx* ctx);
void bvb_SHA256_update(BvbSHA256Ctx* ctx, const uint8_t* data, uint32_t len);
uint8_t* bvb_SHA256_final(BvbSHA256Ctx* ctx);

void bvb_SHA512_init(BvbSHA512Ctx* ctx);
void bvb_SHA512_update(BvbSHA512Ctx* ctx, const uint8_t* data, uint32_t len);
uint8_t* bvb_SHA512_final(BvbSHA512Ctx* ctx);

#ifdef __cplusplus
}
#endif

#endif  /* _BVB_SYSDEPS_H */
