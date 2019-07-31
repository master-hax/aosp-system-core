/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <endian.h>

#include <android-base/file.h>
#include <ext4_utils/ext4_utils.h>
#include <gtest/gtest.h>
#include <libavb/libavb.h>
#include <openssl/sha.h>
#include <sparse/sparse.h>

#include <libvbmeta/reader.h>
#include <libvbmeta/super_vbmeta_format.h>
#include <libvbmeta/writer.h>

#define FAKE_PARTITION_SIZE 8192

using SparsePtr = std::unique_ptr<sparse_file, decltype(&sparse_file_destroy)>;
bool WriteFakeAVBFooter(int fd, uint64_t vbmeta_offset, uint64_t vbmeta_size,
                        uint8_t start_symbol, uint8_t end_symbol) {
  std::unique_ptr<uint8_t[]> buffer =
      std::make_unique<uint8_t[]>(FAKE_PARTITION_SIZE);

  memset(buffer.get(), 0xcc, FAKE_PARTITION_SIZE);

  // Write Fake AvbFooter
  uint64_t offset = be64toh(vbmeta_offset);
  uint64_t size = be64toh(vbmeta_size);
  memcpy(&buffer[FAKE_PARTITION_SIZE - AVB_FOOTER_SIZE], AVB_FOOTER_MAGIC,
         AVB_FOOTER_MAGIC_LEN);
  memcpy(&buffer[FAKE_PARTITION_SIZE - AVB_FOOTER_SIZE + 20], &offset,
         sizeof(uint64_t));
  memcpy(&buffer[FAKE_PARTITION_SIZE - AVB_FOOTER_SIZE + 28], &size,
         sizeof(uint64_t));

  // Write Fake vbmeta
  memset(&buffer[vbmeta_offset], start_symbol, sizeof(uint8_t));
  memset(&buffer[vbmeta_offset + vbmeta_size - 1], end_symbol, sizeof(uint8_t));

  SparsePtr file(sparse_file_new(512, FAKE_PARTITION_SIZE),
                 sparse_file_destroy);
  sparse_file_add_data(file.get(), buffer.get(), FAKE_PARTITION_SIZE, 0);
  return sparse_file_write(file.get(), fd, false, true, false);
}

TEST(SuperVBMetaTest, SuperVBMetaBasic) {
  std::map<std::string, std::pair<uint8_t, uint8_t>> vbmetas;
  vbmetas.emplace("system", std::make_pair(0xaa, 0xbb));
  vbmetas.emplace("vendor", std::make_pair(0xcc, 0xdd));
  vbmetas.emplace("product", std::make_pair(0xee, 0xff));

  TemporaryDir td;

  TemporaryFile system_tf(std::string(td.path));
  std::string system_path(system_tf.path);
  WriteFakeAVBFooter(system_tf.fd, 10, 30, 0xaa, 0xbb);
  system_tf.release();

  TemporaryFile vendor_tf(std::string(td.path));
  std::string vendor_path(vendor_tf.path);
  WriteFakeAVBFooter(vendor_tf.fd, 20, 20, 0xcc, 0xdd);
  vendor_tf.release();

  TemporaryFile product_tf(std::string(td.path));
  std::string product_path(product_tf.path);
  WriteFakeAVBFooter(product_tf.fd, 30, 10, 0xee, 0xff);
  product_tf.release();

  std::string super_path(td.path);
  super_path.append("/super.img");

  std::string vbmeta_path(td.path);
  vbmeta_path.append("/super_vbmeta.img");

  std::stringstream cmd;
  cmd << "lpmake"
      << " --metadata-size " << 512 << " --block-size " << 512
      << " --super-name "
      << "super"
      << " --metadata-slots " << 2 << " --device "
      << "super"
      << ":" << 6 * FAKE_PARTITION_SIZE << ":" << 0 << ":" << 0
      << " --partition "
      << "system"
      << ":readonly:" << FAKE_PARTITION_SIZE << ":default"
      << " --image "
      << "system"
      << "=" << system_path << " --partition "
      << "vendor"
      << ":readonly:" << FAKE_PARTITION_SIZE << ":default"
      << " --image "
      << "vendor"
      << "=" << vendor_path << " --partition "
      << "product"
      << ":readonly:" << FAKE_PARTITION_SIZE << ":default"
      << " --image "
      << "product"
      << "=" << product_path << " --output=" << super_path
      << " --vbmeta=" << vbmeta_path;

  int rc = system(cmd.str().c_str());
  ASSERT_TRUE(WIFEXITED(rc));
  ASSERT_EQ(WEXITSTATUS(rc), 0);

  android::base::unique_fd super_fd(
      open(super_path.c_str(), O_RDONLY | O_CLOEXEC));
  EXPECT_GT(super_fd.get(), 0);

  android::base::unique_fd vbmeta_fd(
      open(vbmeta_path.c_str(), O_RDONLY | O_CLOEXEC));
  EXPECT_GT(vbmeta_fd.get(), 0);

  SuperVBMeta super_vbmeta;
  EXPECT_TRUE(
      android::fs_mgr::ReadSuperVBMeta(vbmeta_fd.get(), 0, &super_vbmeta));

  // Check the size of super vbmeta is a multiple of SUPER_VBMETA_TOTAL_SIZE
  uint64_t super_vbmeta_size = get_file_size(vbmeta_fd.get());
  EXPECT_EQ(super_vbmeta_size, SUPER_VBMETA_TOTAL_SIZE);
  EXPECT_EQ(super_vbmeta_size % SUPER_VBMETA_TOTAL_SIZE, 0);

  // Check Super VBMeta Primary and Backup equal
  SuperVBMeta super_vbmeta_primary;
  EXPECT_TRUE(android::fs_mgr::ReadSuperPrimaryVBMeta(vbmeta_fd.get(),
                                                      &super_vbmeta_primary));
  SuperVBMeta super_vbmeta_backup;
  EXPECT_TRUE(android::fs_mgr::ReadSuperBackupVBMeta(
      vbmeta_fd.get(), &super_vbmeta_backup, SUPER_VBMETA_TOTAL_SIZE));
  EXPECT_EQ(android::fs_mgr::SerializeSuperVBMeta(super_vbmeta_primary),
            android::fs_mgr::SerializeSuperVBMeta(super_vbmeta_backup));

  // Check SuperAVBFooter Checksum
  std::string serial_super_vbmeta =
      android::fs_mgr::SerializeSuperVBMeta(super_vbmeta);
  std::string serial_removed_checksum(serial_super_vbmeta);
  serial_removed_checksum.replace(16, 32, 32, 0);
  uint8_t test_checksum[32];
  ::SHA256(reinterpret_cast<const uint8_t *>(serial_removed_checksum.c_str()),
           super_vbmeta.header.total_size, test_checksum);
  EXPECT_EQ(memcmp(super_vbmeta.header.checksum, test_checksum, 32), 0);

  // Check partition vbmeta start-end
  for (const auto &partition : super_vbmeta.descriptors) {
    EXPECT_EQ(android::fs_mgr::ReadDataFromSuper(super_fd.get(),
                                                 partition.vbmeta_offset),
              vbmetas[partition.partition_name].first);
    EXPECT_EQ(android::fs_mgr::ReadDataFromSuper(super_fd.get(),
                                                 partition.vbmeta_offset +
                                                     partition.vbmeta_size - 1),
              vbmetas[partition.partition_name].second);
  }
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}