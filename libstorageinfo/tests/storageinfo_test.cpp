/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include <storage_info.h>
#include <unistd.h>
#include <climits>
#include <string>

using std::string;

static string get_full_file_path(const string& file) {
    return android::base::GetExecutableDirectory() + "/" + file;
}

TEST(libstorage, nofile) {
    string fname = get_full_file_path("nofile.xml");
    auto info = StorageInfo::NewStorageInfo(fname);
    ASSERT_TRUE(info == nullptr);
}

TEST(libstorage, empty) {
    string fname = get_full_file_path("empty.xml");

    auto info = StorageInfo::NewStorageInfo(fname);
    ASSERT_TRUE(info != nullptr);

    auto& pt = info->GetPartitionTables();
    ASSERT_EQ(size_t(0), pt.size());
}

TEST(libstorage, parse_error_no_label) {
    string fname = get_full_file_path("error_no_label.xml");
    auto info = StorageInfo::NewStorageInfo(fname);
    ASSERT_TRUE(info == nullptr);
}

TEST(libstorage, parse_error_no_type) {
    string fname = get_full_file_path("error_no_type.xml");
    auto info = StorageInfo::NewStorageInfo(fname);
    ASSERT_TRUE(info == nullptr);
}

TEST(libstorage, parse_error_malformed) {
    string fname = get_full_file_path("error_malformed.xml");
    auto info = StorageInfo::NewStorageInfo(fname);
    ASSERT_TRUE(info == nullptr);
}

TEST(libstorage, valid) {
    string fname = get_full_file_path("valid.xml");

    auto info = StorageInfo::NewStorageInfo(fname);
    ASSERT_TRUE(info != nullptr);
    auto& pt = info->GetPartitionTables();
    ASSERT_EQ(size_t(4), pt.size());
    ASSERT_EQ(StorageType::kUfs, info->GetType());

    // validate first partition table
    const auto pt0 = pt[0];
    ASSERT_EQ(0U, pt0.lun);
    ASSERT_EQ(PartitionType::kGpt, pt0.type);
    ASSERT_STREQ("f91a098d-c3db-47ee-a4e1-ffcf432c1977", pt0.disk_guid.c_str());
    ASSERT_EQ(1U, pt0.partitions.size());
    // validate first partition
    auto& pt0p1 = pt0.partitions[0];
    ASSERT_STREQ("v0p0", pt0p1.name.c_str());
    ASSERT_STREQ("e213c3f0-a901-4351-baf6-404fbe9fbe3a", pt0p1.type.c_str());
    ASSERT_TRUE(pt0p1.guid.empty());
    ASSERT_TRUE(pt0p1.file_name.empty());
    ASSERT_TRUE(pt0p1.group.empty());
    ASSERT_EQ(size_t(1024 * 1024), pt0p1.size);
    ASSERT_FALSE(pt0p1.bootable);
    ASSERT_FALSE(pt0p1.readonly);
    ASSERT_FALSE(pt0p1.extend);
    ASSERT_FALSE(pt0p1.erase_block_align);

    // validate second partition table
    const auto pt1 = pt[1];
    ASSERT_EQ(1U, pt1.lun);
    ASSERT_EQ(PartitionType::kGpt, pt1.type);
    ASSERT_STREQ("f80dfb18-9a0c-405a-99c3-be3950f92517", pt1.disk_guid.c_str());
    ASSERT_EQ(3U, pt1.partitions.size());
    // validate first partition
    auto& pt1p1 = pt1.partitions[0];
    ASSERT_STREQ("v1p0", pt1p1.name.c_str());
    ASSERT_STREQ("b3bb9113-60b5-4c6c-bd46-2c7025294422", pt1p1.type.c_str());
    ASSERT_STREQ("group1", pt1p1.group.c_str());
    ASSERT_EQ(size_t(1 * 1024), pt1p1.size);
    ASSERT_FALSE(pt1p1.bootable);
    ASSERT_TRUE(pt1p1.readonly);
    // validate second partition
    auto& pt1p2 = pt1.partitions[1];
    ASSERT_STREQ("v1p1", pt1p2.name.c_str());
    ASSERT_STREQ("b6eb6159-10ea-45f4-baaf-37d16aff7db5", pt1p2.type.c_str());
    ASSERT_EQ(size_t(2048 * 1024), pt1p2.size);
    ASSERT_TRUE(pt1p2.bootable);
    ASSERT_FALSE(pt1p2.readonly);
    ASSERT_TRUE(pt1p2.erase_block_align);
    // validate third partition
    auto& pt1p3 = pt1.partitions[2];
    ASSERT_STREQ("v1pad", pt1p3.name.c_str());
    ASSERT_STREQ("00000000-0000-0000-0000-000000000000", pt1p3.type.c_str());
    ASSERT_EQ(size_t(0), pt1p3.size);
    ASSERT_TRUE(pt1p3.extend);

    // validate third partition table
    const auto pt2 = pt[2];
    ASSERT_EQ(5U, pt2.lun);
    ASSERT_EQ(PartitionType::kGpt, pt2.type);
    ASSERT_TRUE(pt2.disk_guid.empty());
    ASSERT_EQ(2U, pt2.partitions.size());
    // validate first partition
    auto& pt2p1 = pt2.partitions[0];
    ASSERT_STREQ("v5p0", pt2p1.name.c_str());
    ASSERT_STREQ("b8fd47d5-598a-4abd-bfab-c8cf81b53339", pt2p1.type.c_str());
    ASSERT_EQ(size_t(1234 * 1024), pt2p1.size);
    ASSERT_STREQ("v5p0.img", pt2p1.file_name.c_str());
    // validate second partition
    auto& pt2p2 = pt2.partitions[1];
    ASSERT_STREQ("v5p1", pt2p2.name.c_str());
    ASSERT_STREQ("18c08f94-12ba-4159-bb8a-b4b15f01be67", pt2p2.type.c_str());
    ASSERT_EQ(size_t(2048 * 1024), pt2p2.size);
    ASSERT_STREQ("v5p1.img", pt2p2.file_name.c_str());
    ASSERT_STREQ("group2", pt2p2.group.c_str());

    // validate fourth partition table
    const auto pt3 = pt[3];
    ASSERT_EQ(6U, pt3.lun);
    ASSERT_EQ(PartitionType::kGpt, pt3.type);
    ASSERT_TRUE(pt3.disk_guid.empty());
    ASSERT_EQ(1U, pt3.partitions.size());
}
