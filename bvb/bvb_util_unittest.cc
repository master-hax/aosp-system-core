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
  unsigned int n;

  n = 42;
  h.header_version_major = htobe32(n); n++;
  h.header_version_minor = htobe32(n); n++;
  h.authentication_data_block_size = htobe64(n); n++;
  h.auxilary_data_block_size = htobe64(n); n++;
  h.payload_data_block_size = htobe64(n); n++;
  h.algorithm_type = htobe32(n); n++;
  h.hash_offset = htobe64(n); n++;
  h.hash_size = htobe64(n); n++;
  h.signature_offset = htobe64(n); n++;
  h.signature_size = htobe64(n); n++;
  h.public_key_offset = htobe64(n); n++;
  h.public_key_size = htobe64(n); n++;
  h.properties_offset = htobe64(n); n++;
  h.properties_size = htobe64(n); n++;
  h.rollback_index = htobe64(n); n++;
  h.kernel_offset = htobe64(n); n++;
  h.kernel_size = htobe64(n); n++;
  h.initrd_offset = htobe64(n); n++;
  h.initrd_size = htobe64(n); n++;
  h.kernel_addr = htobe64(n); n++;
  h.initrd_addr = htobe64(n); n++;

  bvb_boot_image_header_to_host_byte_order(&h, &s);

  n = 42;
  EXPECT_EQ(n, s.header_version_major); n++;
  EXPECT_EQ(n, s.header_version_minor); n++;
  EXPECT_EQ(n, s.authentication_data_block_size); n++;
  EXPECT_EQ(n, s.auxilary_data_block_size); n++;
  EXPECT_EQ(n, s.payload_data_block_size); n++;
  EXPECT_EQ(n, s.algorithm_type); n++;
  EXPECT_EQ(n, s.hash_offset); n++;
  EXPECT_EQ(n, s.hash_size); n++;
  EXPECT_EQ(n, s.signature_offset); n++;
  EXPECT_EQ(n, s.signature_size); n++;
  EXPECT_EQ(n, s.public_key_offset); n++;
  EXPECT_EQ(n, s.public_key_size); n++;
  EXPECT_EQ(n, s.properties_offset); n++;
  EXPECT_EQ(n, s.properties_size); n++;
  EXPECT_EQ(n, s.rollback_index); n++;
  EXPECT_EQ(n, s.kernel_offset); n++;
  EXPECT_EQ(n, s.kernel_size); n++;
  EXPECT_EQ(n, s.initrd_offset); n++;
  EXPECT_EQ(n, s.initrd_size); n++;
  EXPECT_EQ(n, s.kernel_addr); n++;
  EXPECT_EQ(n, s.initrd_addr); n++;

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
  unsigned int n;

  n = 42;
  h.key_num_bits = htobe32(n); n++;
  h.n0inv = htobe32(n); n++;

  bvb_rsa_public_key_header_to_host_byte_order(&h, &s);

  n = 42;
  EXPECT_EQ(n, s.key_num_bits); n++;
  EXPECT_EQ(n, s.n0inv); n++;
}
