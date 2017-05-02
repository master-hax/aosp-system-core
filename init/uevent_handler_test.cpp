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

#include "uevent_handler.h"

#include <string>
#include <vector>

#include <android-base/scopeguard.h>
#include <gtest/gtest.h>

class UeventHandlerTester {
  public:
    void AddPlatformDevice(const std::string& path) {
        uevent uevent = {
            .action = "add", .subsystem = "platform", .path = path,
        };
        uevent_handler_.HandlePlatformDeviceEvent(&uevent);
    }

    void RemovePlatformDevice(const std::string& path) {
        uevent uevent = {
            .action = "remove", .subsystem = "platform", .path = path,
        };
        uevent_handler_.HandlePlatformDeviceEvent(&uevent);
    }

    void TestGetSymlinks(const std::string& platform_device_name, uevent* uevent,
                         const std::vector<std::string> expected_links, bool block) {
        AddPlatformDevice(platform_device_name);
        auto platform_device_remover = android::base::make_scope_guard(
            [this, &platform_device_name]() { RemovePlatformDevice(platform_device_name); });

        std::vector<std::string> result;
        if (block) {
            result = uevent_handler_.GetBlockDeviceSymlinks(uevent);
        } else {
            result = uevent_handler_.GetCharacterDeviceSymlinks(uevent);
        }

        auto expected_size = expected_links.size();
        ASSERT_EQ(expected_size, result.size());
        if (expected_size == 0) return;

        // Explicitly iterate so the results are visible if a failure occurs
        for (unsigned int i = 0; i < expected_size; ++i) {
            EXPECT_EQ(expected_links[i], result[i]);
        }
    }

  private:
    UeventHandler uevent_handler_;
};

TEST(uevent_handler, PlatformDeviceList) {
    PlatformDeviceList platform_device_list;

    platform_device_list.Add("/devices/platform/some_device_name");
    platform_device_list.Add("/devices/platform/some_device_name/longer");
    platform_device_list.Add("/devices/platform/other_device_name");
    EXPECT_EQ(3U, platform_device_list.size());

    std::string out_path;
    EXPECT_FALSE(platform_device_list.Find("/devices/platform/not_found", &out_path));
    EXPECT_EQ("", out_path);

    EXPECT_FALSE(platform_device_list.Find("/devices/platform/some_device_name_with_same_prefix",
                                           &out_path));

    EXPECT_TRUE(platform_device_list.Find("/devices/platform/some_device_name/longer/longer_child",
                                          &out_path));
    EXPECT_EQ("/devices/platform/some_device_name/longer", out_path);

    EXPECT_TRUE(
        platform_device_list.Find("/devices/platform/some_device_name/other_child", &out_path));
    EXPECT_EQ("/devices/platform/some_device_name", out_path);
}

TEST(uevent_handler, get_character_device_symlinks_success) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/usb/usb_device/name/tty2-1:1.0",
        .subsystem = "tty",
    };
    std::vector<std::string> expected_result{"/dev/usb/ttyname"};

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, false);
}

TEST(uevent_handler, get_character_device_symlinks_no_pdev_match) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/device/name/tty2-1:1.0", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, false);
}

TEST(uevent_handler, get_character_device_symlinks_nothing_after_platform_device) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, false);
}

TEST(uevent_handler, get_character_device_symlinks_no_usb_found) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/bad/bad/", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, false);
}

TEST(uevent_handler, get_character_device_symlinks_no_roothub) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/usb/", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, false);
}

TEST(uevent_handler, get_character_device_symlinks_no_usb_device) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/usb/usb_device/", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, false);
}

TEST(uevent_handler, get_character_device_symlinks_no_final_slash) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/usb/usb_device/name", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, false);
}

TEST(uevent_handler, get_character_device_symlinks_no_final_name) {
    const char* platform_device = "/devices/platform/some_device_name";
    uevent uevent = {
        .path = "/devices/platform/some_device_name/usb/usb_device//", .subsystem = "tty",
    };
    std::vector<std::string> expected_result;

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, false);
}

TEST(uevent_handler, get_block_device_symlinks_success_platform) {
    // These are actual paths from bullhead
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0",
        .partition_name = "",
        .partition_num = -1,
    };
    std::vector<std::string> expected_result{"/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0"};

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, true);
}

TEST(uevent_handler, get_block_device_symlinks_success_platform_with_partition) {
    // These are actual paths from bullhead
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = "modem",
        .partition_num = 1,
    };
    std::vector<std::string> expected_result{
        "/dev/block/platform/soc.0/f9824900.sdhci/by-name/modem",
        "/dev/block/platform/soc.0/f9824900.sdhci/by-num/p1",
        "/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0p1",
    };

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, true);
}

TEST(uevent_handler, get_block_device_symlinks_success_platform_with_partition_only_num) {
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = "",
        .partition_num = 1,
    };
    std::vector<std::string> expected_result{
        "/dev/block/platform/soc.0/f9824900.sdhci/by-num/p1",
        "/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0p1",
    };

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, true);
}

TEST(uevent_handler, get_block_device_symlinks_success_platform_with_partition_only_name) {
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    uevent uevent = {
        .path = "/devices/soc.0/f9824900.sdhci/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = "modem",
        .partition_num = -1,
    };
    std::vector<std::string> expected_result{
        "/dev/block/platform/soc.0/f9824900.sdhci/by-name/modem",
        "/dev/block/platform/soc.0/f9824900.sdhci/mmcblk0p1",
    };

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, true);
}

TEST(uevent_handler, get_block_device_symlinks_success_pci) {
    const char* platform_device = "/devices/do/not/match";
    uevent uevent = {
        .path = "/devices/pci0000:00/0000:00:1f.2/mmcblk0", .partition_name = "", .partition_num = -1,
    };
    std::vector<std::string> expected_result{"/dev/block/pci/pci0000:00/0000:00:1f.2/mmcblk0"};

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, true);
}

TEST(uevent_handler, get_block_device_symlinks_pci_bad_format) {
    const char* platform_device = "/devices/do/not/match";
    uevent uevent = {
        .path = "/devices/pci//mmcblk0", .partition_name = "", .partition_num = -1,
    };
    std::vector<std::string> expected_result{};

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, true);
}

TEST(uevent_handler, get_block_device_symlinks_success_vbd) {
    const char* platform_device = "/devices/do/not/match";
    uevent uevent = {
        .path = "/devices/vbd-1234/mmcblk0", .partition_name = "", .partition_num = -1,
    };
    std::vector<std::string> expected_result{"/dev/block/vbd/1234/mmcblk0"};

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, true);
}

TEST(uevent_handler, get_block_device_symlinks_vbd_bad_format) {
    const char* platform_device = "/devices/do/not/match";
    uevent uevent = {
        .path = "/devices/vbd-/mmcblk0", .partition_name = "", .partition_num = -1,
    };
    std::vector<std::string> expected_result{};

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, true);
}

TEST(uevent_handler, get_block_device_symlinks_no_matches) {
    const char* platform_device = "/devices/soc.0/f9824900.sdhci";
    uevent uevent = {
        .path = "/devices/soc.0/not_the_device/mmc_host/mmc0/mmc0:0001/block/mmcblk0p1",
        .partition_name = "",
        .partition_num = -1,
    };
    std::vector<std::string> expected_result;

    UeventHandlerTester uevent_handler_tester_;
    uevent_handler_tester_.TestGetSymlinks(platform_device, &uevent, expected_result, true);
}

TEST(uevent_handler, sanitize_null) {
    sanitize_partition_name(nullptr);
}

TEST(uevent_handler, sanitize_empty) {
    std::string empty;
    sanitize_partition_name(&empty);
    EXPECT_EQ(0u, empty.size());
}

TEST(uevent_handler, sanitize_allgood) {
    std::string good =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "_-.";
    std::string good_copy = good;
    sanitize_partition_name(&good);
    EXPECT_EQ(good_copy, good);
}

TEST(uevent_handler, sanitize_somebad) {
    std::string string = "abc!@#$%^&*()";
    sanitize_partition_name(&string);
    EXPECT_EQ("abc__________", string);
}

TEST(uevent_handler, sanitize_allbad) {
    std::string string = "!@#$%^&*()";
    sanitize_partition_name(&string);
    EXPECT_EQ("__________", string);
}

TEST(uevent_handler, sanitize_onebad) {
    std::string string = ")";
    sanitize_partition_name(&string);
    EXPECT_EQ("_", string);
}

TEST(uevent_handler, DevPermissionsMatchNormal) {
    // Basic from ueventd.rc
    // /dev/null                 0666   root       root
    Permissions permissions("/dev/null", 0666, 0, 0);
    EXPECT_TRUE(permissions.Match("/dev/null"));
    EXPECT_FALSE(permissions.Match("/dev/nullsuffix"));
    EXPECT_FALSE(permissions.Match("/dev/nul"));
    EXPECT_EQ(0666U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(0U, permissions.gid());
}

TEST(uevent_handler, DevPermissionsMatchPrefix) {
    // Prefix from ueventd.rc
    // /dev/dri/*                0666   root       graphics
    Permissions permissions("/dev/dri/*", 0666, 0, 1000);
    EXPECT_TRUE(permissions.Match("/dev/dri/some_dri_device"));
    EXPECT_TRUE(permissions.Match("/dev/dri/some_other_dri_device"));
    EXPECT_TRUE(permissions.Match("/dev/dri/"));
    EXPECT_FALSE(permissions.Match("/dev/dr/non_match"));
    EXPECT_EQ(0666U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1000U, permissions.gid());
}

TEST(uevent_handler, DevPermissionsMatchWildcard) {
    // Wildcard example
    // /dev/device*name                0666   root       graphics
    Permissions permissions("/dev/device*name", 0666, 0, 1000);
    EXPECT_TRUE(permissions.Match("/dev/devicename"));
    EXPECT_TRUE(permissions.Match("/dev/device123name"));
    EXPECT_TRUE(permissions.Match("/dev/deviceabcname"));
    EXPECT_FALSE(permissions.Match("/dev/device123name/subdevice"));
    EXPECT_FALSE(permissions.Match("/dev/deviceame"));
    EXPECT_EQ(0666U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1000U, permissions.gid());
}

TEST(uevent_handler, DevPermissionsMatchWildcardPrefix) {
    // Wildcard+Prefix example
    // /dev/device*name*                0666   root       graphics
    Permissions permissions("/dev/device*name*", 0666, 0, 1000);
    EXPECT_TRUE(permissions.Match("/dev/devicename"));
    EXPECT_TRUE(permissions.Match("/dev/device123name"));
    EXPECT_TRUE(permissions.Match("/dev/deviceabcname"));
    EXPECT_TRUE(permissions.Match("/dev/device123namesomething"));
    // FNM_PATHNAME doesn't match '/' with *
    EXPECT_FALSE(permissions.Match("/dev/device123name/something"));
    EXPECT_FALSE(permissions.Match("/dev/deviceame"));
    EXPECT_EQ(0666U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1000U, permissions.gid());
}

TEST(uevent_handler, SysfsPermissionsMatchWithSubsystemNormal) {
    // /sys/devices/virtual/input/input*   enable      0660  root   input
    SysfsPermissions permissions("/sys/devices/virtual/input/input*", "enable", 0660, 0, 1001);
    EXPECT_TRUE(permissions.MatchWithSubsystem("/sys/devices/virtual/input/input0", "input"));
    EXPECT_FALSE(permissions.MatchWithSubsystem("/sys/devices/virtual/input/not_input0", "input"));
    EXPECT_EQ(0660U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1001U, permissions.gid());
}

TEST(uevent_handler, SysfsPermissionsMatchWithSubsystemClass) {
    // /sys/class/input/event*   enable      0660  root   input
    SysfsPermissions permissions("/sys/class/input/event*", "enable", 0660, 0, 1001);
    EXPECT_TRUE(permissions.MatchWithSubsystem(
        "/sys/devices/soc.0/f9924000.i2c/i2c-2/2-0020/input/input0/event0", "input"));
    EXPECT_FALSE(permissions.MatchWithSubsystem(
        "/sys/devices/soc.0/f9924000.i2c/i2c-2/2-0020/input/input0/not_event0", "input"));
    EXPECT_FALSE(permissions.MatchWithSubsystem(
        "/sys/devices/soc.0/f9924000.i2c/i2c-2/2-0020/input/input0/event0", "not_input"));
    EXPECT_EQ(0660U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1001U, permissions.gid());
}

TEST(uevent_handler, SysfsPermissionsMatchWithSubsystemBus) {
    // /sys/bus/i2c/devices/i2c-*   enable      0660  root   input
    SysfsPermissions permissions("/sys/bus/i2c/devices/i2c-*", "enable", 0660, 0, 1001);
    EXPECT_TRUE(permissions.MatchWithSubsystem("/sys/devices/soc.0/f9967000.i2c/i2c-5", "i2c"));
    EXPECT_FALSE(permissions.MatchWithSubsystem("/sys/devices/soc.0/f9967000.i2c/not-i2c", "i2c"));
    EXPECT_FALSE(
        permissions.MatchWithSubsystem("/sys/devices/soc.0/f9967000.i2c/i2c-5", "not_i2c"));
    EXPECT_EQ(0660U, permissions.perm());
    EXPECT_EQ(0U, permissions.uid());
    EXPECT_EQ(1001U, permissions.gid());
}
