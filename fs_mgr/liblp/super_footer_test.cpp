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

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <libavb/libavb.h>
#include <libvbmeta/builder.h>
#include <libvbmeta/footer_format.h>
#include <libvbmeta/reader.h>
#include <libvbmeta/writer.h>
#include <openssl/sha.h>
#include <sparse/sparse.h>

#include <endian.h>

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

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

TEST(superfooter, SuperAVBFooter) {
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
      << "=" << system_path.c_str() << " --partition "
      << "vendor"
      << ":readonly:" << FAKE_PARTITION_SIZE << ":default"
      << " --image "
      << "vendor"
      << "=" << vendor_path.c_str() << " --partition "
      << "product"
      << ":readonly:" << FAKE_PARTITION_SIZE << ":default"
      << " --image "
      << "product"
      << "=" << product_path.c_str() << " --output=" << super_path.c_str()
      << " --footer ";

  int rc = system(cmd.str().c_str());
  ASSERT_TRUE(WIFEXITED(rc));
  ASSERT_EQ(WEXITSTATUS(rc), 0);

  android::base::unique_fd super_fd(
      open(super_path.c_str(), O_RDONLY | O_CLOEXEC));
  EXPECT_GT(super_fd.get(), 0);

  SuperFooter super_footer;
  EXPECT_TRUE(android::fs_mgr::ReadSuperFooter(
      super_fd.get(), 6 * FAKE_PARTITION_SIZE, &super_footer));

  SuperAVBFooter super_avb_footer;
  EXPECT_TRUE(android::fs_mgr::ReadSuperAvbFooter(
      super_fd.get(), super_footer.avbfooter_offset, &super_avb_footer));

  // Check SuperAVBFooter Checksum
  std::string serial_super_avb_footer =
      android::fs_mgr::SerializeSuperAVBFooter(super_avb_footer);
  std::string serial_removed_checksum(serial_super_avb_footer);
  serial_removed_checksum.replace(16, 32, 32, 0);
  uint8_t test_checksum[32];
  ::SHA256(reinterpret_cast<const uint8_t *>(serial_removed_checksum.c_str()),
           super_avb_footer.header.total_size, test_checksum);
  EXPECT_EQ(memcmp(super_avb_footer.header.checksum, test_checksum, 32), 0);

  // Check partition vbmeta start-end
  for (const auto &partition : super_avb_footer.descriptors) {
    EXPECT_EQ(android::fs_mgr::ReadDataFromSuper(super_fd.get(),
                                                 partition.vbmeta_offset),
              vbmetas[partition.partition_name].first);
    EXPECT_EQ(android::fs_mgr::ReadDataFromSuper(super_fd.get(),
                                                 partition.vbmeta_offset +
                                                     partition.vbmeta_size - 1),
              vbmetas[partition.partition_name].second);
  }
}