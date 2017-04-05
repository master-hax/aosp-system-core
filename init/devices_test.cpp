/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "devices.h"

#include <vector>

#include <android-base/scopeguard.h>
#include <gtest/gtest.h>

void add_platform_device(const char* path);
void remove_platform_device(const char* path);
std::vector<std::string> get_character_device_symlinks(uevent* uevent);

void test_get_character_device_symlinks(const std::string& platform_device_name,
                                        const std::string& uevent_path,
                                        const std::string& uevent_subsystem,
                                        std::vector<std::string>::size_type expected_size,
                                        const std::string& expected_link) {
    add_platform_device(platform_device_name.c_str());
    auto platform_device_remover = android::base::make_scope_guard(
        [&platform_device_name]() { remove_platform_device(platform_device_name.c_str()); });

    uevent uevent = {
        .path = uevent_path.c_str(), .subsystem = uevent_subsystem.c_str(),
    };

    auto result = get_character_device_symlinks(&uevent);
    ASSERT_EQ(expected_size, result.size());
    if (expected_size > 0) {
        EXPECT_EQ(expected_link, result[0]);
    }
}

TEST(devices, get_character_device_symlinks_success) {
    test_get_character_device_symlinks(
        "/device/platform/some_device_name",
        "/device/platform/some_device_name/usb/usb_device/name/tty2-1:1.0", "tty", 1u,
        "/dev/usb/ttyname");
}

TEST(devices, get_character_device_symlinks_no_pdev_match) {
    test_get_character_device_symlinks("/device/platform/some_device_name",
                                       "/device/name/tty2-1:1.0", "tty", 0u, "");
}

TEST(devices, get_character_device_symlinks_nothing_after_platform_device) {
    test_get_character_device_symlinks("/device/platform/some_device_name",
                                       "/device/platform/some_device_name", "tty", 0u, "");
}

TEST(devices, get_character_device_symlinks_no_usb_found) {
    test_get_character_device_symlinks("/device/platform/some_device_name",
                                       "/device/platform/some_device_name/bad/bad/", "tty", 0u, "");
}

TEST(devices, get_character_device_symlinks_no_roothub) {
    test_get_character_device_symlinks("/device/platform/some_device_name",
                                       "/device/platform/some_device_name/usb/", "tty", 0u, "");
}

TEST(devices, get_character_device_symlinks_no_usb_device) {
    test_get_character_device_symlinks("/device/platform/some_device_name",
                                       "/device/platform/some_device_name/usb/usb_device/", "tty",
                                       0u, "");
}

TEST(devices, get_character_device_symlinks_no_final_slash) {
    test_get_character_device_symlinks("/device/platform/some_device_name",
                                       "/device/platform/some_device_name/usb/usb_device/name",
                                       "tty", 0u, "");
}

void sanitize(std::string* string);

TEST(devices, sanitize_null) {
    sanitize(nullptr);
}

TEST(devices, sanitize_empty) {
    std::string empty;
    sanitize(&empty);
    EXPECT_EQ(0u, empty.size());
}

TEST(devices, sanitize_allgood) {
    std::string good =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "_-.";
    std::string good_copy = good;
    sanitize(&good);
    EXPECT_EQ(good_copy, good);
}

TEST(devices, sanitize_somebad) {
    std::string string = "abc!@#$%^&*()";
    sanitize(&string);
    EXPECT_EQ("abc__________", string);
}

TEST(devices, sanitize_allbad) {
    std::string string = "!@#$%^&*()";
    sanitize(&string);
    EXPECT_EQ("__________", string);
}

TEST(devices, sanitize_onebad) {
    std::string string = ")";
    sanitize(&string);
    EXPECT_EQ("_", string);
}
