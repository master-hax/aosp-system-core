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

#include <gtest/gtest.h>

std::vector<std::string> get_character_device_symlinks(const std::string& path,
                                                       const std::string& subsystem);

TEST(devices, get_character_device_symlinks_no_usb) {
    const char* parent = "/device/name/tty2-1:1.0";
    const char* subsystem = "tty";
    auto result = get_character_device_symlinks(parent, subsystem);
    ASSERT_EQ(0u, result.size());
}

TEST(devices, get_character_device_symlinks_one_dir_deep) {
    const char* parent = "/usb/name";
    const char* subsystem = "tty";
    auto result = get_character_device_symlinks(parent, subsystem);
    ASSERT_EQ(0u, result.size());
}

TEST(devices, get_character_device_symlinks_two_dirs_deep) {
    const char* parent = "/usb/name/name2";
    const char* subsystem = "tty";
    auto result = get_character_device_symlinks(parent, subsystem);
    ASSERT_EQ(0u, result.size());
}

TEST(devices, get_character_device_symlinks) {
    const char* parent = "/usb/usb_device/name/tty2-1:1.0";
    const char* subsystem = "tty";
    auto result = get_character_device_symlinks(parent, subsystem);
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ("/dev/usb/ttyname", result[0]);
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
