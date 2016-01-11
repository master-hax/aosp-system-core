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


#include "bvb_util.h"

uint32_t bvb_be32toh(uint32_t in) {
  uint8_t* d = (uint8_t*) &in;
  uint32_t ret;
  ret  = ((uint32_t) d[0]) << 24;
  ret |= ((uint32_t) d[1]) << 16;
  ret |= ((uint32_t) d[2]) << 8;
  ret |= ((uint32_t) d[3]);
  return ret;
}

uint64_t bvb_be64toh(uint64_t in) {
  uint8_t* d = (uint8_t*) &in;
  uint64_t ret;
  ret  = ((uint64_t) d[0]) << 56;
  ret |= ((uint64_t) d[1]) << 48;
  ret |= ((uint64_t) d[2]) << 40;
  ret |= ((uint64_t) d[3]) << 32;
  ret |= ((uint64_t) d[4]) << 24;
  ret |= ((uint64_t) d[5]) << 16;
  ret |= ((uint64_t) d[6]) << 8;
  ret |= ((uint64_t) d[7]);
  return ret;
}

#define _BCONV32(name) dest->name = bvb_be32toh(dest->name)
#define _BCONV64(name) dest->name = bvb_be64toh(dest->name)

void bvb_boot_image_header_to_host_byte_order(const BvbBootImageHeader* header,
                                              BvbBootImageHeader* dest)
{
  bvb_memcpy(dest, header, sizeof(BvbBootImageHeader));

  _BCONV32(header_version_major);
  _BCONV32(header_version_minor);

  _BCONV64(authentication_data_block_size);
  _BCONV64(auxilary_data_block_size);
  _BCONV64(payload_data_block_size);

  _BCONV32(algorithm_type);

  _BCONV64(hash_offset);
  _BCONV64(hash_size);

  _BCONV64(signature_offset);
  _BCONV64(signature_size);

  _BCONV64(public_key_offset);
  _BCONV64(public_key_size);

  _BCONV64(properties_offset);
  _BCONV64(properties_size);

  _BCONV64(rollback_index);

  _BCONV64(kernel_offset);
  _BCONV64(kernel_size);

  _BCONV64(initrd_offset);
  _BCONV64(initrd_size);

  _BCONV64(device_tree_offset);
  _BCONV64(device_tree_size);

  _BCONV64(kernel_addr);
  _BCONV64(initrd_addr);
}

void bvb_rsa_public_key_header_to_host_byte_order(const BvbRSAPublicKeyHeader* header,
                                                  BvbRSAPublicKeyHeader* dest)
{
  bvb_memcpy(dest, header, sizeof(BvbRSAPublicKeyHeader));

  _BCONV32(key_num_bits);
  _BCONV32(n0inv);
}
