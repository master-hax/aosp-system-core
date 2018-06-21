/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <map>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <libdm/loop_control.h>
#include <time.h>

using namespace std;
using namespace android::dm;
using unique_fd = android::base::unique_fd;

TEST(libdm, HasMinimumTargets) {
    DeviceMapper& dm = DeviceMapper::Instance();
    vector<DmTargetTypeInfo> targets;
    ASSERT_TRUE(dm.GetAvailableTargets(&targets));

    map<string, DmTargetTypeInfo> by_name;
    for (const auto& target : targets) {
        by_name[target.name()] = target;
    }

    auto iter = by_name.find("linear");
    EXPECT_NE(iter, by_name.end());
}

static unique_fd TempFile(size_t disk_size) {
    unique_fd fd(syscall(__NR_memfd_create, "fake_disk", MFD_ALLOW_SEALING));
    if (fd < 0) {
        perror("memfd_create");
        return {};
    }
    if (ftruncate(fd, disk_size) < 0) {
        perror("ftruncate");
        return {};
    }
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) < 0) {
        perror("fcntl");
        return {};
    }
    return fd;
}

// Helper to ensure that device mapper devices are released.
class TempDevice {
  public:
    TempDevice(const std::string& name, const DmTable& table)
        : dm_(DeviceMapper::Instance()), name_(name), valid_(false) {
        valid_ = dm_.CreateDevice(name, table);
    }
    ~TempDevice() {
        if (valid_) {
            dm_.DeleteDevice(name_);
        }
    }
    bool Destroy() {
        if (!valid_) {
            return false;
        }
        valid_ = false;
        return dm_.DeleteDevice(name_);
    }
    std::string path() const {
        std::string device_path;
        if (!dm_.GetDmDevicePathByName(name_, &device_path)) {
            return "";
        }
        return device_path;
    }
    const std::string& name() const { return name_; }
    bool valid() const { return valid_; }

  private:
    DeviceMapper& dm_;
    std::string name_;
    bool valid_;
};

TEST(libdm, DmLinear) {
    unique_fd tmp1(TempFile(4096));
    ASSERT_GE(tmp1, 0);
    unique_fd tmp2(TempFile(4096));
    ASSERT_GE(tmp2, 0);

    // Create two different files. These will back two separate loop devices.
    const char message1[] = "Hello! This is sector 1.";
    const char message2[] = "Goodbye. This is sector 2.";
    ASSERT_TRUE(android::base::WriteFully(tmp1, message1, sizeof(message1)));
    ASSERT_TRUE(android::base::WriteFully(tmp2, message2, sizeof(message2)));

    LoopDevice loop_a(tmp1);
    ASSERT_TRUE(loop_a.valid());
    LoopDevice loop_b(tmp2);
    ASSERT_TRUE(loop_b.valid());

    // Define a 2-sector device, with each sector mapping to the first sector
    // of one of our loop devices.
    DmTable table;
    ASSERT_TRUE(table.AddTarget(make_unique<DmTargetLinear>(0, 1, loop_a.device(), 0)));
    ASSERT_TRUE(table.AddTarget(make_unique<DmTargetLinear>(1, 1, loop_b.device(), 0)));
    ASSERT_TRUE(table.valid());

    TempDevice dev("libdm-test-dm-linear", table);
    ASSERT_TRUE(dev.valid());
    ASSERT_FALSE(dev.path().empty());

    // Note: a scope is needed to ensure that there are no open descriptors
    // when we go to close the device.
    {
        unique_fd dev_fd(open(dev.path().c_str(), O_RDWR));
        ASSERT_GE(dev_fd, 0);

        // Test that each sector of our device is correctly mapped to each loop
        // device.
        char sector[512];
        ASSERT_TRUE(android::base::ReadFully(dev_fd, sector, sizeof(sector)));
        ASSERT_EQ(strncmp(sector, message1, sizeof(message1)), 0);
        ASSERT_TRUE(android::base::ReadFully(dev_fd, sector, sizeof(sector)));
        ASSERT_EQ(strncmp(sector, message2, sizeof(message2)), 0);
    }

    // Normally the TestDevice destructor would delete this, but at least one
    // test should ensure that device deletion works.
    ASSERT_TRUE(dev.Destroy());
}
