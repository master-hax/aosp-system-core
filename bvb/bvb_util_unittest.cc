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

#include <string.h>

#include <gtest/gtest.h>

#include "bvb_util.h"

TEST(UtilTest, BootImageHeaderByteswap)
{
  BvbBootImageHeader h;
  BvbBootImageHeader s;
  uint32_t n32;
  uint64_t n64;

  n32 = 0x11223344;
  n64 = 0x1122334455667788;

  h.header_version_major = htobe32(n32); n32++;
  h.header_version_minor = htobe32(n32); n32++;
  h.authentication_data_block_size = htobe64(n64); n64++;
  h.auxilary_data_block_size = htobe64(n64); n64++;
  h.payload_data_block_size = htobe64(n64); n64++;
  h.algorithm_type = htobe32(n32); n32++;
  h.hash_offset = htobe64(n64); n64++;
  h.hash_size = htobe64(n64); n64++;
  h.signature_offset = htobe64(n64); n64++;
  h.signature_size = htobe64(n64); n64++;
  h.public_key_offset = htobe64(n64); n64++;
  h.public_key_size = htobe64(n64); n64++;
  h.properties_offset = htobe64(n64); n64++;
  h.properties_size = htobe64(n64); n64++;
  h.rollback_index = htobe64(n64); n64++;
  h.kernel_offset = htobe64(n64); n64++;
  h.kernel_size = htobe64(n64); n64++;
  h.initrd_offset = htobe64(n64); n64++;
  h.initrd_size = htobe64(n64); n64++;
  h.kernel_addr = htobe64(n64); n64++;
  h.initrd_addr = htobe64(n64); n64++;

  bvb_boot_image_header_to_host_byte_order(&h, &s);

  n32 = 0x11223344;
  n64 = 0x1122334455667788;

  EXPECT_EQ(n32, s.header_version_major); n32++;
  EXPECT_EQ(n32, s.header_version_minor); n32++;
  EXPECT_EQ(n64, s.authentication_data_block_size); n64++;
  EXPECT_EQ(n64, s.auxilary_data_block_size); n64++;
  EXPECT_EQ(n64, s.payload_data_block_size); n64++;
  EXPECT_EQ(n32, s.algorithm_type); n32++;
  EXPECT_EQ(n64, s.hash_offset); n64++;
  EXPECT_EQ(n64, s.hash_size); n64++;
  EXPECT_EQ(n64, s.signature_offset); n64++;
  EXPECT_EQ(n64, s.signature_size); n64++;
  EXPECT_EQ(n64, s.public_key_offset); n64++;
  EXPECT_EQ(n64, s.public_key_size); n64++;
  EXPECT_EQ(n64, s.properties_offset); n64++;
  EXPECT_EQ(n64, s.properties_size); n64++;
  EXPECT_EQ(n64, s.rollback_index); n64++;
  EXPECT_EQ(n64, s.kernel_offset); n64++;
  EXPECT_EQ(n64, s.kernel_size); n64++;
  EXPECT_EQ(n64, s.initrd_offset); n64++;
  EXPECT_EQ(n64, s.initrd_size); n64++;
  EXPECT_EQ(n64, s.kernel_addr); n64++;
  EXPECT_EQ(n64, s.initrd_addr); n64++;

  // If new fields are added, the following will fail. This is to
  // remind that byteswapping code (in bvb_util.c) and unittests for
  // this should be updated.
  static_assert(offsetof(BvbBootImageHeader, reserved) == 4256,
                "Remember to unittest byteswapping of newly added fields");
}

TEST(UtilTest, RSAPublicKeyHeaderByteswap)
{
  BvbRSAPublicKeyHeader h;
  BvbRSAPublicKeyHeader s;
  uint32_t n32;
  uint64_t n64;

  n32 = 0x11223344;
  n64 = 0x1122334455667788;

  h.key_num_bits = htobe32(n32); n32++;
  h.n0inv = htobe32(n32); n32++;

  bvb_rsa_public_key_header_to_host_byte_order(&h, &s);

  n32 = 0x11223344;
  n64 = 0x1122334455667788;

  EXPECT_EQ(n32, s.key_num_bits); n32++;
  EXPECT_EQ(n32, s.n0inv); n32++;
}

TEST(UtilTest, SafeAddition) {
  uint64_t value;
  uint64_t pow2_60 = 1ULL << 60;

  value = 2;
  EXPECT_NE(0, bvb_safe_add_to(&value, 5));
  EXPECT_EQ(7UL, value);

  /* These should not overflow */
  value = 1*pow2_60;
  EXPECT_NE(0, bvb_safe_add_to(&value, 2*pow2_60));
  EXPECT_EQ(3*pow2_60, value);
  value = 7*pow2_60;
  EXPECT_NE(0, bvb_safe_add_to(&value, 8*pow2_60));
  EXPECT_EQ(15*pow2_60, value);
  value = 9*pow2_60;
  EXPECT_NE(0, bvb_safe_add_to(&value, 3*pow2_60));
  EXPECT_EQ(12*pow2_60, value);
  value = 0xfffffffffffffffcUL;
  EXPECT_NE(0, bvb_safe_add_to(&value, 2));
  EXPECT_EQ(0xfffffffffffffffeUL, value);

  /* These should overflow. */
  value = 8*pow2_60;
  EXPECT_EQ(0, bvb_safe_add_to(&value, 8*pow2_60));
  value = 0xfffffffffffffffcUL;
  EXPECT_EQ(0, bvb_safe_add_to(&value, 4));
}
