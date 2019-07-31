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

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <libavb/libavb.h>
#include <openssl/sha.h>
#include <sparse/sparse.h>

#include "reader.h"
#include "vbmeta_table_format.h"
#include "writer.h"

#define FAKE_DATA_SIZE 40960
#define FAKE_PARTITION_SIZE FAKE_DATA_SIZE * 25
#define FAKE_SUPER_SIZE FAKE_PARTITION_SIZE * 10

using android::base::Result;
using SparsePtr = std::unique_ptr<sparse_file, decltype(&sparse_file_destroy)>;

static uint64_t get_file_size(int fd) {
    struct stat sb;
    EXPECT_NE(-1, fstat(fd, &sb));
    return sb.st_size;
}

bool GenerateVBMetaForPartition(int fd, const std::string& file_name,
                                const std::string& partition_name) {
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(FAKE_DATA_SIZE);
    for (size_t c = 0; c < FAKE_DATA_SIZE; c++) {
        buffer[c] = uint8_t(c);
    }

    SparsePtr file(sparse_file_new(512 /* block size */, FAKE_DATA_SIZE), sparse_file_destroy);
    EXPECT_TRUE(file);
    EXPECT_EQ(0, sparse_file_add_data(file.get(), buffer.get(), FAKE_DATA_SIZE,
                                      0 /* offset in blocks */));
    EXPECT_EQ(0, sparse_file_write(file.get(), fd, false /* gz */, true /* sparse */,
                                   false /* crc */));

    std::stringstream cmd;
    cmd << "avbtool add_hashtree_footer"
        << " --image " << file_name << " --partition_name " << partition_name
        << " --partition_size " << FAKE_PARTITION_SIZE << " --algorithm SHA256_RSA2048"
        << " --key external/avb/test/data/testkey_rsa2048.pem";

    int rc = system(cmd.str().c_str());
    EXPECT_TRUE(WIFEXITED(rc));
    EXPECT_EQ(WEXITSTATUS(rc), 0);
    return true;
}

TEST(VBMetaTableTest, VBMetaTableBasic) {
    TemporaryDir td;

    TemporaryFile system_tf(std::string(td.path));
    std::string system_path(system_tf.path);
    GenerateVBMetaForPartition(system_tf.fd, system_path, "system");
    system_tf.release();

    TemporaryFile vendor_tf(std::string(td.path));
    std::string vendor_path(vendor_tf.path);
    GenerateVBMetaForPartition(vendor_tf.fd, vendor_path, "vendor");
    vendor_tf.release();

    TemporaryFile product_tf(std::string(td.path));
    std::string product_path(product_tf.path);
    GenerateVBMetaForPartition(product_tf.fd, product_path, "product");
    product_tf.release();

    std::string super_path(td.path);
    super_path.append("/super.img");

    std::string vbmeta_path(td.path);
    vbmeta_path.append("/vbmeta_table.img");

    std::stringstream cmd;
    cmd << "lpmake"
        << " --metadata-size " << 512 << " --block-size " << 512 << " --super-name "
        << "super"
        << " --metadata-slots " << 2 << " --device "
        << "super"
        << ":" << FAKE_SUPER_SIZE << ":" << 0 << ":" << 0 << " --partition "
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
        << "=" << product_path << " --output=" << super_path << " --vbmeta=" << vbmeta_path;

    int rc = system(cmd.str().c_str());
    ASSERT_TRUE(WIFEXITED(rc));
    ASSERT_EQ(WEXITSTATUS(rc), 0);

    android::base::unique_fd super_fd(open(super_path.c_str(), O_RDONLY | O_CLOEXEC));
    EXPECT_GT(super_fd.get(), 0);

    android::base::unique_fd vbmeta_fd(open(vbmeta_path.c_str(), O_RDONLY | O_CLOEXEC));
    EXPECT_GT(vbmeta_fd.get(), 0);

    VBMetaTable table;
    EXPECT_TRUE(android::fs_mgr::ReadVBMetaTable(vbmeta_fd.get(), 0, &table));

    // Check the size of vbmeta table is VBMETA_TABLE_MAX_SIZE * 2 ( Primary + Backup )
    uint64_t vbmeta_table_size = get_file_size(vbmeta_fd.get());
    EXPECT_EQ(vbmeta_table_size, VBMETA_TABLE_MAX_SIZE * 2);

    // Check VBMeta Primary is equal to Backup
    VBMetaTable vbmeta_table_primary;
    EXPECT_TRUE(android::fs_mgr::ReadPrimaryVBMetaTable(vbmeta_fd.get(), &vbmeta_table_primary));
    VBMetaTable vbmeta_table_backup;
    EXPECT_TRUE(android::fs_mgr::ReadBackupVBMetaTable(vbmeta_fd.get(), &vbmeta_table_backup));
    EXPECT_EQ(android::fs_mgr::SerializeVBMetaTable(vbmeta_table_primary),
              android::fs_mgr::SerializeVBMetaTable(vbmeta_table_backup));

    // Check VBMeta Table Header Checksum
    std::string serial_table = android::fs_mgr::SerializeVBMetaTable(table);
    std::string serial_removed_checksum(serial_table);
    // Replace checksum 32 bytes (starts at 16th byte) with 0
    serial_removed_checksum.replace(16, 32, 32, 0);
    uint8_t test_checksum[32];
    ::SHA256(reinterpret_cast<const uint8_t*>(serial_removed_checksum.c_str()),
             table.header.total_size, test_checksum);
    EXPECT_EQ(memcmp(table.header.checksum, test_checksum, 32), 0);

    // Check partition vbmeta content
    for (const auto& partition : table.descriptors) {
        std::unique_ptr<uint8_t[]> s = std::make_unique<uint8_t[]>(partition.vbmeta_size);
        EXPECT_TRUE(android::base::ReadFullyAtOffset(super_fd.get(), s.get(), partition.vbmeta_size,
                                                     partition.vbmeta_offset));

        // Check vbmeta content
        EXPECT_EQ(AVB_VBMETA_VERIFY_RESULT_OK,
                  avb_vbmeta_image_verify(s.get(), partition.vbmeta_size, NULL, NULL));
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}