// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <sys/mount.h>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fstab/fstab.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>

static int GetVsrLevel() {
    return android::base::GetIntProperty("ro.vendor.api_level", -1);
}

TEST(fs, PartitionTypes) {
    android::fs_mgr::Fstab fstab;
    ASSERT_TRUE(android::fs_mgr::ReadFstabFromFile("/proc/mounts", &fstab));

    auto& dm = android::dm::DeviceMapper::Instance();

    std::string super_bdev, userdata_bdev;
    ASSERT_TRUE(android::base::Readlink("/dev/block/by-name/super", &super_bdev));
    ASSERT_TRUE(android::base::Readlink("/dev/block/by-name/userdata", &userdata_bdev));

    int vsr_level = GetVsrLevel();

    for (const auto& entry : fstab) {
        std::string parent_bdev = entry.blk_device;
        while (true) {
            auto basename = android::base::Basename(parent_bdev);
            if (!android::base::StartsWith(basename, "dm-")) {
                break;
            }

            auto parent = dm.GetParentBlockDeviceByPath(parent_bdev);
            if (!parent || *parent == parent_bdev) {
                break;
            }
            parent_bdev = *parent;
        }

        if (parent_bdev == userdata_bdev ||
            android::base::StartsWith(parent_bdev, "/dev/block/loop")) {
            if (entry.flags & MS_RDONLY) {
                // APEXes should not be F2FS.
                EXPECT_NE(entry.fs_type, "f2fs");
            }
            continue;
        }

        if (vsr_level <= 32) {
            continue;
        }
        if (vsr_level == 33 && parent_bdev != super_bdev) {
            // Only check for dynamic partitions at this VSR level.
            continue;
        }

        if (entry.flags & MS_RDONLY) {
            EXPECT_EQ(entry.fs_type, "erofs") << entry.mount_point;
        } else {
            EXPECT_NE(entry.fs_type, "ext4") << entry.mount_point;
        }
    }
}
