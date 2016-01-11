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

#include <iostream>

#include <endian.h>
#include <inttypes.h>
#include <string.h>

#include <base/files/file_util.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "bvb_unittest_util.h"
#include "bvb_util.h"
#include "bvb_verify.h"
#include "bvb_property.h"

class VerifyTest : public BaseBVBToolTest {
public:
  VerifyTest() {}

protected:

  // Helper function for ModificationDetection test. Modifies
  // boot_image_ in a number of places in the sub-array at |offset| of
  // size |length| and checks that bvb_verify_boot_image() returns
  // |expected_result|.
  bool test_modification(BvbVerifyResult expected_result,
                         size_t offset, size_t length);

};

TEST_F(VerifyTest, BootImageStructSize)
{
  EXPECT_EQ(8192UL, sizeof(BvbBootImageHeader));
}

TEST_F(VerifyTest, CheckSHA256RSA2048)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));
  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, CheckSHA256RSA4096)
{
  GenerateBootImage("SHA256_RSA4096", "", 0
                    , base::FilePath("test/testkey_rsa4096.pem"));
  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, CheckSHA256RSA8192)
{
  GenerateBootImage("SHA256_RSA8192", "", 0,
                    base::FilePath("test/testkey_rsa8192.pem"));
  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, CheckSHA512RSA2048)
{
  GenerateBootImage("SHA512_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));
  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, CheckSHA512RSA4096)
{
  GenerateBootImage("SHA512_RSA4096", "", 0,
                    base::FilePath("test/testkey_rsa4096.pem"));
  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, CheckSHA512RSA8192)
{
  GenerateBootImage("SHA512_RSA8192", "", 0,
                    base::FilePath("test/testkey_rsa8192.pem"));
  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, CheckUnsigned)
{
  GenerateBootImage("", "", 0, base::FilePath(""));
  EXPECT_EQ(BVB_VERIFY_RESULT_OK_NOT_SIGNED,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, BadMagic)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));
  boot_image_[0] = 'A';
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}


TEST_F(VerifyTest, MajorVersionCheck)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader *h =
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data());
  h->header_version_major = htobe32(1 + be32toh(h->header_version_major));
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, BlockSizesAddUpToLength)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader *h =
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data());
  BvbBootImageHeader backup = *h;

  h->authentication_data_block_size = htobe32(0);
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
  *h = backup;

  h->auxilary_data_block_size = htobe32(0);
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
  *h = backup;

  h->payload_data_block_size = htobe32(0);
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
  *h = backup;

  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, BlockSizesMultipleOf64)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader *h =
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data());
  BvbBootImageHeader backup = *h;

  h->authentication_data_block_size =
      htobe32(be32toh(h->authentication_data_block_size) - 32);
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size() - 32,
                                  NULL, NULL));
  *h = backup;

  h->auxilary_data_block_size =
      htobe32(be32toh(h->auxilary_data_block_size) - 32);
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size() - 32,
                                  NULL, NULL));
  *h = backup;

  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, HashOutOfBounds)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader *h =
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data());

  // Check we catch when hash data goes out of bounds.
  h->hash_offset = htobe64(4);
  h->hash_size = htobe64(be64toh(h->authentication_data_block_size));
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, SignatureOutOfBounds)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader *h =
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data());

  // Check we catch when signature data goes out of bounds.
  h->signature_offset = htobe64(4);
  h->signature_size = htobe64(be64toh(h->authentication_data_block_size));
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, PublicKeyOutOfBounds)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader *h =
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data());

  // Check we catch when public key data goes out of bounds.
  h->public_key_offset = htobe64(4);
  h->public_key_size = htobe64(be64toh(h->auxilary_data_block_size));
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, KernelOutOfBounds)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader *h =
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data());

  // Check we catch when kernel data goes out of bounds.
  h->kernel_offset = htobe64(4);
  h->kernel_size = htobe64(be64toh(h->payload_data_block_size));
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, InitrdOutOfBounds)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader *h =
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data());

  // Check we catch when initrd data goes out of bounds.
  h->initrd_offset = htobe64(4);
  h->initrd_size = htobe64(be64toh(h->payload_data_block_size));
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, InvalidAlgorithmField)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader *h =
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data());
  BvbBootImageHeader backup = *h;

  // Check we bail on unknown algorithm.
  h->algorithm_type = htobe32(_BVB_ALGORITHM_NUM_TYPES);
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
  *h = backup;
  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

TEST_F(VerifyTest, PublicKeyBlockTooSmall)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader *h =
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data());
  BvbBootImageHeader backup = *h;

  // Check we bail if the auxilary data block is too small.
  uint64_t change = be64toh(h->auxilary_data_block_size) - 64;
  h->auxilary_data_block_size = htobe64(change);
  EXPECT_EQ(BVB_VERIFY_RESULT_INVALID_BOOT_IMAGE_HEADER,
            bvb_verify_boot_image(boot_image_.data(),
                                  boot_image_.size() - change,
                                  NULL, NULL));
  *h = backup;
  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));
}

bool VerifyTest::test_modification(BvbVerifyResult expected_result,
                                    size_t offset, size_t length) {
  uint8_t *d = reinterpret_cast<uint8_t*>(boot_image_.data());
  const int kNumCheckpoints = 16;

  // Test |kNumCheckpoints| modifications in the start, middle, and
  // end of given sub-array.
  for (int n = 0; n <= kNumCheckpoints; n++) {
    size_t o = std::min(length*n/kNumCheckpoints, length - 1) + offset;
    d[o] ^= 0x80;
    BvbVerifyResult result = bvb_verify_boot_image(boot_image_.data(),
                                                   boot_image_.size(),
                                                   NULL, NULL);
    d[o] ^= 0x80;
    if (result != expected_result)
      return false;
  }

  return true;
}

#include <iostream>

TEST_F(VerifyTest, ModificationDetection)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  NULL, NULL));

  BvbBootImageHeader h;
  bvb_boot_image_header_to_host_byte_order(
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data()), &h);

  size_t header_block_offset = 0;
  size_t authentication_block_offset = header_block_offset + sizeof(BvbBootImageHeader);
  size_t auxilary_block_offset = authentication_block_offset + h.authentication_data_block_size;
  size_t payload_block_offset = auxilary_block_offset + h.auxilary_data_block_size;

  // Ensure we detect modification of the header data block. Do this
  // in a field that's not validated so INVALID_BOOT_IMAGE_HEADER
  // isn't returned.
  EXPECT_TRUE(test_modification(BVB_VERIFY_RESULT_HASH_MISMATCH,
                                offsetof(BvbBootImageHeader, kernel_cmdline),
                                BVB_KERNEL_CMDLINE_MAX_LEN));
  // Also check the |reserved| field.
  EXPECT_TRUE(test_modification(BVB_VERIFY_RESULT_HASH_MISMATCH,
                                offsetof(BvbBootImageHeader, reserved),
                                sizeof(BvbBootImageHeader().reserved)));

  // Ensure we detect modifications in the auxilary data block.
  EXPECT_TRUE(test_modification(BVB_VERIFY_RESULT_HASH_MISMATCH,
                                auxilary_block_offset,
                                h.auxilary_data_block_size));

  // Ensure we detect modifications in the payload key data block.
  EXPECT_TRUE(test_modification(BVB_VERIFY_RESULT_HASH_MISMATCH,
                                payload_block_offset,
                                h.payload_data_block_size));

  // Modifications in the hash part of the Authentication data block
  // should also yield HASH_MISMATCH. This is because the hash check
  // compares the calculated hash against the stored hash.
  EXPECT_TRUE(test_modification(BVB_VERIFY_RESULT_HASH_MISMATCH,
                                authentication_block_offset + h.hash_offset,
                                h.hash_size));

  // Modifications in the signature part of the Authentication data
  // block, should not cause a hash mismatch ... but will cause a
  // signature mismatch.
  EXPECT_TRUE(test_modification(BVB_VERIFY_RESULT_SIGNATURE_MISMATCH,
                                authentication_block_offset +
                                  h.signature_offset,
                                h.signature_size));

  // Mofications outside the hash and signature parts of the
  // Authentication data block are not detected. This is because it's
  // not part of the hash calculation.
  uint64_t offset = h.signature_offset + h.signature_size;
  ASSERT_LT(h.hash_offset, h.signature_offset);
  ASSERT_LT(offset + 1, h.authentication_data_block_size);
  EXPECT_TRUE(test_modification(BVB_VERIFY_RESULT_OK,
                                authentication_block_offset + offset,
                                h.authentication_data_block_size - offset));
}
