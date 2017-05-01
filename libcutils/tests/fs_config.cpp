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

#include <string>

#include <gtest/gtest.h>

#include <android-base/macros.h>
#include <android-base/strings.h>

#include "../fs_config.c"

static void check_one(const struct fs_path_config* paths, const size_t size,
                      const std::string& prefix, const std::string& alternate) {
    for (size_t idx = 0; idx < size; ++idx) {
        if (!paths[idx].prefix) continue;
        std::string path(paths[idx].prefix);
        if (android::base::StartsWith(path, prefix.c_str())) {
            path = alternate + path.substr(prefix.length());
            size_t second;
            for (second = 0; second < size; ++second) {
                if (!paths[second].prefix) continue;
                if (path == paths[second].prefix) break;
            }
            if (second >= size) {
                EXPECT_STREQ((prefix + path.substr(alternate.length())).c_str(), path.c_str());
            }
        }
    }
}

static void check_two(const struct fs_path_config* paths, const size_t size,
                      const std::string& prefix) {
    std::string alternate = "system/" + prefix;
    check_one(paths, size, prefix, alternate);
    check_one(paths, size, alternate, prefix);
}

TEST(fs_config, vendor_dirs_alias) {
    check_two(android_dirs, arraysize(android_dirs), "vendor/");
}

TEST(fs_config, vendor_files_alias) {
    check_two(android_files, arraysize(android_files), "vendor/");
}

TEST(fs_config, oem_dirs_alias) {
    check_two(android_dirs, arraysize(android_dirs), "oem/");
}

TEST(fs_config, oem_files_alias) {
    check_two(android_files, arraysize(android_files), "oem/");
}

TEST(fs_config, odm_dirs_alias) {
    check_two(android_dirs, arraysize(android_dirs), "odm/");
}

TEST(fs_config, odm_files_alias) {
    check_two(android_files, arraysize(android_files), "odm/");
}
