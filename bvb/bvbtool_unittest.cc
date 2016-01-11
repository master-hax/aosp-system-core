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

class BVBToolTest : public BaseBVBToolTest {
public:
  BVBToolTest() {}
};

// This test ensure that the version is increased in both
// bvb_boot_image.h and the bvb tool.
TEST_F(BVBToolTest, BvbVersionInSync)
{
  base::FilePath path = testdir_.Append("version.txt");
  EXPECT_COMMAND(0,
                 "./bvbtool version > %s",
                 path.value().c_str());
  int64_t file_size;
  std::vector<char> file_contents;
  ASSERT_TRUE(base::GetFileSize(path, &file_size));
  file_contents.resize(file_size + 1, '\0');
  ASSERT_TRUE(base::ReadFile(path,
                             file_contents.data(),
                             file_contents.size()));
  std::string printed_version = std::string(file_contents.data());
  base::TrimWhitespaceASCII(printed_version, base::TRIM_ALL, &printed_version);
  std::string expected_version = base::StringPrintf("%d.%d",
                                                    BVB_MAJOR_VERSION,
                                                    BVB_MINOR_VERSION);
  EXPECT_EQ(printed_version, expected_version);
}

TEST_F(BVBToolTest, ExtractPublicKey)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  base::FilePath public_key_path = testdir_.Append("public_key.bin");
  EXPECT_COMMAND(0,
                 "./bvbtool extract_public_key --key test/testkey_rsa2048.pem"
                 " --output %s",
                 public_key_path.value().c_str());

  int64_t file_size;
  std::vector<uint8_t> key_data;
  ASSERT_TRUE(base::GetFileSize(public_key_path, &file_size));
  key_data.resize(file_size);
  ASSERT_TRUE(base::ReadFile(public_key_path,
                             reinterpret_cast<char*>(key_data.data()),
                             key_data.size()));

  BvbBootImageHeader h;
  bvb_boot_image_header_to_host_byte_order(
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data()), &h);
  uint8_t *d = reinterpret_cast<uint8_t*>(boot_image_.data());
  size_t auxilary_data_block_offset = sizeof(BvbBootImageHeader) + h.authentication_data_block_size;
  EXPECT_GT(h.auxilary_data_block_size, key_data.size());
  EXPECT_EQ(0, memcmp(key_data.data(),
                      d + auxilary_data_block_offset + h.public_key_offset,
                      key_data.size()));
}

TEST_F(BVBToolTest, PayloadsAreCorrect)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader h;
  bvb_boot_image_header_to_host_byte_order(
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data()), &h);

  uint8_t *d = reinterpret_cast<uint8_t*>(boot_image_.data()) +
      sizeof(BvbBootImageHeader) +
      h.authentication_data_block_size +
      h.auxilary_data_block_size;

  // Check that the kernel, initrd and device_tree are inserted
  // correctly into the image.
  for (int n = 0; n < 3; n++) {
    std::string paths[3] = {"test/dummy_kernel.bin",
                            "test/dummy_initrd.bin",
                            "test/dummy_device_tree.bin"};
    base::FilePath path(paths[n]);

    int64_t file_size;
    std::vector<uint8_t> file_data;
    ASSERT_TRUE(base::GetFileSize(path, &file_size));
    file_data.resize(file_size);
    ASSERT_TRUE(base::ReadFile(path,
                               reinterpret_cast<char*>(file_data.data()),
                               file_data.size()));

    switch (n) {
      case 0:
        // kernel
        EXPECT_EQ(65536U, file_data.size());
        EXPECT_EQ(file_data.size(), h.kernel_size);
        EXPECT_EQ(0, memcmp(file_data.data(),
                            d + h.kernel_offset,
                            file_data.size()));
        break;
      case 1:
        // initrd
        EXPECT_EQ(131072U, file_data.size());
        EXPECT_EQ(file_data.size(), h.initrd_size);
        EXPECT_EQ(0, memcmp(file_data.data(),
                            d + h.initrd_offset,
                            file_data.size()));
        break;
      case 2:
        // device tree
        EXPECT_EQ(16384U, file_data.size());
        EXPECT_EQ(file_data.size(), h.device_tree_size);
        EXPECT_EQ(0, memcmp(file_data.data(),
                            d + h.device_tree_offset,
                            file_data.size()));
        break;
      default:
        ASSERT_TRUE(false);
        break;
    }
  }
}

TEST_F(BVBToolTest, CheckCmdline)
{
  std::string cmdline("init=/sbin/init ro x y z");
  GenerateBootImage("SHA256_RSA2048", cmdline, 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader h;
  bvb_boot_image_header_to_host_byte_order(
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data()), &h);

  EXPECT_EQ(0, ::strcmp(cmdline.c_str(),
                        reinterpret_cast<const char*>(h.kernel_cmdline)));
}

TEST_F(BVBToolTest, CheckAddresses)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"),
                    "--kernel_addr 0x42 --initrd_addr 43");

  BvbBootImageHeader h;
  bvb_boot_image_header_to_host_byte_order(
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data()), &h);

  EXPECT_EQ(0x42U, h.kernel_addr);
  EXPECT_EQ(43U, h.initrd_addr);
}

TEST_F(BVBToolTest, CheckProperties)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"),
                    "--prop foo:brillo "
                    "--prop bar:chromeos "
                    "--prop prisoner:24601 "
                    "--prop hexnumber:0xcafe "
                    "--prop hexnumber_capital:0xCAFE "
                    "--prop large_hexnumber:0xfedcba9876543210 "
                    "--prop larger_than_uint64:0xfedcba98765432101 "
                    "--prop almost_a_number:423x "
                    "--prop_from_file blob:test/small_blob.bin "
                    );

  BvbBootImageHeader h;
  bvb_boot_image_header_to_host_byte_order(
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data()), &h);

  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  nullptr, nullptr));

  const char *s;
  size_t len;
  uint64_t val;

  // Basic.
  s = bvb_lookup_property(boot_image_.data(), boot_image_.size(),
                          "foo", 0, &len);
  EXPECT_EQ(0, strcmp(s, "brillo"));
  EXPECT_EQ(6U, len);
  s = bvb_lookup_property(boot_image_.data(), boot_image_.size(),
                          "bar", 0, &len);
  EXPECT_EQ(0, strcmp(s, "chromeos"));
  EXPECT_EQ(8U, len);
  s = bvb_lookup_property(boot_image_.data(), boot_image_.size(),
                          "non-existant", 0, &len);
  EXPECT_EQ(0U, len);
  EXPECT_EQ(NULL, s);

  // Numbers.
  EXPECT_NE(0, bvb_lookup_property_uint64(
      boot_image_.data(), boot_image_.size(), "prisoner", 0, &val));
  EXPECT_EQ(24601U, val);

  EXPECT_NE(0, bvb_lookup_property_uint64(
      boot_image_.data(), boot_image_.size(), "hexnumber", 0, &val));
  EXPECT_EQ(0xcafeU, val);

  EXPECT_NE(0, bvb_lookup_property_uint64(
      boot_image_.data(), boot_image_.size(), "hexnumber_capital", 0, &val));
  EXPECT_EQ(0xcafeU, val);

  EXPECT_NE(0, bvb_lookup_property_uint64(
      boot_image_.data(), boot_image_.size(), "large_hexnumber", 0, &val));
  EXPECT_EQ(0xfedcba9876543210U, val);

  // We could catch overflows and return an error ... but we currently don't.
  EXPECT_NE(0, bvb_lookup_property_uint64(
      boot_image_.data(), boot_image_.size(), "larger_than_uint64", 0, &val));
  EXPECT_EQ(0xedcba98765432101U, val);

  // Number-parsing failures.
  EXPECT_EQ(0, bvb_lookup_property_uint64(
      boot_image_.data(), boot_image_.size(), "foo", 0, &val));

  EXPECT_EQ(0, bvb_lookup_property_uint64(
      boot_image_.data(), boot_image_.size(), "almost_a_number", 0, &val));

  // Blobs.
  //
  // test/small_blob.bin is 21 byte file full of NUL-bytes except for
  // the string "brillo ftw!" at index 2 and '\n' at the last byte.
  s = bvb_lookup_property(boot_image_.data(), boot_image_.size(),
                          "blob", 0, &len);
  EXPECT_EQ(21U, len);
  EXPECT_EQ(0, memcmp(s,     "\0\0", 2));
  EXPECT_EQ(0, memcmp(s +  2, "brillo ftw!", 11));
  EXPECT_EQ(0, memcmp(s + 13, "\0\0\0\0\0\0\0", 7));
  EXPECT_EQ('\n', s[20]);
}

TEST_F(BVBToolTest, CheckRollbackIndex)
{
  uint64_t rollback_index = 42;
  GenerateBootImage("SHA256_RSA2048", "", rollback_index,
                    base::FilePath("test/testkey_rsa2048.pem"));

  BvbBootImageHeader h;
  bvb_boot_image_header_to_host_byte_order(
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data()), &h);

  EXPECT_EQ(rollback_index, h.rollback_index);
}

TEST_F(BVBToolTest, CheckPubkeyReturned)
{
  GenerateBootImage("SHA256_RSA2048", "", 0,
                    base::FilePath("test/testkey_rsa2048.pem"));

  const uint8_t* pubkey = NULL;
  size_t pubkey_length = 0;

  EXPECT_EQ(BVB_VERIFY_RESULT_OK,
            bvb_verify_boot_image(boot_image_.data(), boot_image_.size(),
                                  &pubkey, &pubkey_length));

  BvbBootImageHeader h;
  bvb_boot_image_header_to_host_byte_order(
      reinterpret_cast<BvbBootImageHeader*>(boot_image_.data()), &h);

  EXPECT_EQ(pubkey_length, h.public_key_size);

  const uint8_t* expected_pubkey = boot_image_.data() +
      sizeof(BvbBootImageHeader) +
      h.authentication_data_block_size +
      h.public_key_offset;
  EXPECT_EQ(pubkey, expected_pubkey);
}

TEST_F(BVBToolTest, Info)
{
  GenerateBootImage("SHA256_RSA2048", "foobar=cmdline test=42", 0,
                    base::FilePath("test/testkey_rsa2048.pem"),
                    "--prop foo:brillo "
                    "--prop bar:chromeos "
                    "--prop prisoner:24601 "
                    "--prop hexnumber:0xcafe "
                    "--prop hexnumber_capital:0xCAFE "
                    "--prop large_hexnumber:0xfedcba9876543210 "
                    "--prop larger_than_uint64:0xfedcba98765432101 "
                    "--prop almost_a_number:423x "
                    "--prop_from_file blob:test/small_blob.bin "
                    "--prop_from_file large_blob:test/dummy_kernel.bin");

  base::FilePath info_path = testdir_.Append("info_output.txt");
  EXPECT_COMMAND(0,
                 "./bvbtool info_boot_image --image %s --output %s",
                 boot_image_path_.value().c_str(),
                 info_path.value().c_str());

  int64_t file_size;
  std::vector<uint8_t> info_data;
  ASSERT_TRUE(base::GetFileSize(info_path, &file_size));
  info_data.resize(file_size + 1);
  ASSERT_TRUE(base::ReadFile(info_path,
                             reinterpret_cast<char*>(info_data.data()),
                             info_data.size()));

  ASSERT_EQ("Boot Image version:       1.0\n"
            "Header Block:             8192 bytes\n"
            "Authentication Block:     4096 bytes\n"
            "Auxilary Block:           70080 bytes\n"
            "Payload Block:            212992 bytes\n"
            "Algorithm:                SHA256_RSA2048\n"
            "Rollback Index:           0\n"
            "Kernel:                   65536 bytes\n"
            "Initrd:                   131072 bytes\n"
            "Device Tree:              16384 bytes\n"
            "Kernel Load Address:      0x10008000\n"
            "Initrd Load Address:      0x11000000\n"
            "Kernel Cmdline:           foobar=cmdline test=42\n"
            "Properties:\n"
            "    foo: 'brillo'\n"
            "    bar: 'chromeos'\n"
            "    prisoner: '24601'\n"
            "    hexnumber: '0xcafe'\n"
            "    hexnumber_capital: '0xCAFE'\n"
            "    large_hexnumber: '0xfedcba9876543210'\n"
            "    larger_than_uint64: '0xfedcba98765432101'\n"
            "    almost_a_number: '423x'\n"
            "    blob: '\\x00\\x00brillo ftw!\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\n'\n"
            "    large_blob: (65536 bytes)\n",
            std::string((const char*) info_data.data()));
}
