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

#include <gtest/gtest.h>

#include "builder.h"
#include "vbmeta_table_format.h"

using namespace android::fs_mgr;

TEST(BuilderTest, VBMetaTableBasic) {
    std::unique_ptr<VBMetaTableBuilder> builder = std::make_unique<VBMetaTableBuilder>();
    ASSERT_NE(builder, nullptr);

    builder->AddVBMetaInfo(VBMetaInfo{
            static_cast<uint64_t>(6E10) /* vbmeta_offset */,
            static_cast<uint32_t>(8E3) /* vbmeta_size */,
            "system" /* partition_name */,
    });
    builder->AddVBMetaInfo(VBMetaInfo{
            static_cast<uint64_t>(4E10) /* vbmeta_offset */,
            static_cast<uint32_t>(6E3) /* vbmeta_size */,
            "product" /* partition_name */,
    });
    builder->AddVBMetaInfo(VBMetaInfo{
            static_cast<uint64_t>(5E10) /* vbmeta_offset */,
            static_cast<uint32_t>(7E3) /* vbmeta_size */,
            "vendor" /* partition_name */,
    });
    builder->AddVBMetaInfo(VBMetaInfo{
            static_cast<uint64_t>(3E10) /* vbmeta_offset */,
            static_cast<uint32_t>(5E3) /* vbmeta_size */,
            "system" /* partition_name */,
    });
    builder->DeleteVBMetaInfo("vendor" /* partition_name */
    );

    std::unique_ptr<VBMetaTable> table = builder->Export();
    ASSERT_NE(table, nullptr);

    // check for vbmeta table header
    EXPECT_EQ(table->header.magic, VBMETA_TABLE_MAGIC);
    EXPECT_EQ(table->header.major_version, VBMETA_TABLE_MAJOR_VERSION);
    EXPECT_EQ(table->header.minor_version, VBMETA_TABLE_MINOR_VERSION);
    EXPECT_EQ(table->header.header_size, VBMETA_TABLE_HEADER_SIZE);
    EXPECT_EQ(table->header.total_size,
              VBMETA_TABLE_HEADER_SIZE + VBMETA_TABLE_DESCRIPTOR_SIZE * 2 + 13);
    EXPECT_EQ(table->header.descriptors_size, VBMETA_TABLE_DESCRIPTOR_SIZE * 2 + 13);

    // Test for vbmeta table descriptors
    EXPECT_EQ(table->descriptors.size(), 2);

    EXPECT_EQ(table->descriptors[0].vbmeta_offset, 3E10);
    EXPECT_EQ(table->descriptors[0].vbmeta_size, 5E3);
    EXPECT_EQ(table->descriptors[0].partition_name_length, 6);
    for (int i = 0; i < 48; i++) EXPECT_EQ(table->descriptors[0].reserved[i], 0);
    EXPECT_EQ(table->descriptors[0].partition_name, "system");

    EXPECT_EQ(table->descriptors[1].vbmeta_offset, 4E10);
    EXPECT_EQ(table->descriptors[1].vbmeta_size, 6E3);
    EXPECT_EQ(table->descriptors[1].partition_name_length, 7);
    for (int i = 0; i < 48; i++) EXPECT_EQ(table->descriptors[1].reserved[i], 0);
    EXPECT_EQ(table->descriptors[1].partition_name, "product");
}