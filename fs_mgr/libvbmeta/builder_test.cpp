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

#include <libvbmeta/builder.h>
#include <libvbmeta/super_vbmeta_format.h>

using namespace android::fs_mgr;

TEST(BuilderTest, SuperVBMetaBasic) {
  std::unique_ptr<SuperVBMetaBuilder> builder =
      std::make_unique<SuperVBMetaBuilder>();
  ASSERT_NE(builder, nullptr);

  EXPECT_TRUE(builder->Add("system", 3E10, 5E3));
  EXPECT_TRUE(builder->Add("product", 4E10, 6E3));
  EXPECT_TRUE(builder->Add("vendor", 5E10, 7E3));
  EXPECT_TRUE(builder->Delete("vendor"));

  std::unique_ptr<SuperVBMeta> vbmeta = builder->Export();
  ASSERT_NE(vbmeta, nullptr);

  // check for header
  EXPECT_EQ(vbmeta->header.magic, SUPER_VBMETA_MAGIC);
  EXPECT_EQ(vbmeta->header.major_version, SUPER_VBMETA_MAJOR_VERSION);
  EXPECT_EQ(vbmeta->header.minor_version, SUPER_VBMETA_MINOR_VERSION);
  EXPECT_EQ(vbmeta->header.header_size, SUPER_VBMETA_HEADER_SIZE);
  EXPECT_EQ(vbmeta->header.total_size,
            SUPER_VBMETA_HEADER_SIZE + SUPER_VBMETA_DESCRIPTOR_SIZE * 2 + 13);
  EXPECT_EQ(vbmeta->header.descriptors_size,
            SUPER_VBMETA_DESCRIPTOR_SIZE * 2 + 13);

  // Test for descriptors
  EXPECT_EQ(vbmeta->descriptors.size(), 2);

  EXPECT_EQ(vbmeta->descriptors[0].vbmeta_offset, 4E10);
  EXPECT_EQ(vbmeta->descriptors[0].vbmeta_size, 6E3);
  EXPECT_EQ(vbmeta->descriptors[0].partition_name_length, 7);
  for (int i = 0; i < 48; i++)
    EXPECT_EQ(vbmeta->descriptors[0].reserved[i], 0);
  EXPECT_STREQ(vbmeta->descriptors[0].partition_name, "product");

  EXPECT_EQ(vbmeta->descriptors[1].vbmeta_offset, 3E10);
  EXPECT_EQ(vbmeta->descriptors[1].vbmeta_size, 5E3);
  EXPECT_EQ(vbmeta->descriptors[1].partition_name_length, 6);
  for (int i = 0; i < 48; i++)
    EXPECT_EQ(vbmeta->descriptors[1].reserved[i], 0);
  EXPECT_STREQ(vbmeta->descriptors[1].partition_name, "system");
}