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

#ifndef _BVB_UTIL_H
#define _BVB_UTIL_H

#include "bvb_boot_image_header.h"
#include "bvb_rsa.h"
#include "bvb_sysdeps.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32_t bvb_be32toh(uint32_t in);
uint64_t bvb_be64toh(uint64_t in);

void bvb_boot_image_header_to_host_byte_order(const BvbBootImageHeader* header,
                                              BvbBootImageHeader* dest);

void bvb_rsa_public_key_header_to_host_byte_order(const BvbRSAPublicKeyHeader* header,
                                                  BvbRSAPublicKeyHeader* dest);

#ifdef __cplusplus
}
#endif

#endif  /* _BVB_UTIL_H */
