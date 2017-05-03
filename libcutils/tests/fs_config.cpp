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

#include <android-base/file.h>
#include <android-base/strings.h>

#include <private/android_filesystem_config.h>
#include <private/fs_config.h>

extern const struct fs_path_config* __for_testing_only__android_dirs;
extern const struct fs_path_config* __for_testing_only__android_files;

static bool check_unique(std::vector<const char*>& paths, const std::string& name,
                         const std::string& prefix) {
    bool retval = false;

    std::string alternate = "system/" + prefix;

    for (size_t second, idx = 0; idx < paths.size(); ++idx) {
        std::string path(paths[idx]);
        if (android::base::StartsWith(path, prefix.c_str())) {
            path = alternate + path.substr(prefix.size());
            for (second = 0; second < paths.size(); ++second) {
                if (path == paths[second]) {
                    GTEST_LOG_(ERROR) << "duplicate alias paths in " << name << ": " << paths[idx]
                                      << " and " << paths[second] << " (remove latter)";
                    retval = true;
                    break;
                }
            }
        } else if (android::base::StartsWith(path, alternate.c_str())) {
            path = prefix + path.substr(alternate.size());
            for (second = 0; second < paths.size(); ++second) {
                if (path == paths[second]) break;
            }
            if (second >= paths.size()) {
                GTEST_LOG_(ERROR) << "replace path in " << name << ": " << paths[idx] << " with "
                                  << path;
                retval = true;
            }
        }
    }
    return retval;
}

static bool check_unique(const struct fs_path_config* paths, const char* type_name,
                         const std::string& prefix) {
    std::string name("system/core/libcutils/fs_config.cpp:android_");
    name += type_name;
    name += "[]";

    bool retval = false;
    static constexpr size_t max_idx = 4096;
    std::vector<const char*> paths_tmp;
    for (size_t idx = 0; paths[idx].prefix; ++idx) {
        if (idx > max_idx) {
            GTEST_LOG_(WARNING) << name << ": has no end (missing null prefix)";
            retval = true;
            break;
        }
        paths_tmp.push_back(paths[idx].prefix);
    }

    return check_unique(paths_tmp, name, prefix) || retval;
}

static bool check_unique(const std::string& config, const std::string& prefix) {
    int retval = false;

    std::string data;
    if (!android::base::ReadFileToString(config, &data)) return retval;

    const struct fs_path_config_from_file* pc =
        reinterpret_cast<const fs_path_config_from_file*>(data.c_str());
    size_t len = data.size();

    std::vector<const char*> paths_tmp;
    while (len > 0) {
        uint16_t host_len = pc->len;
        if (host_len > len) {
            GTEST_LOG_(WARNING) << config << ": corrupted";
            retval = true;
            break;
        }
        paths_tmp.push_back(pc->prefix);

        pc = reinterpret_cast<const fs_path_config_from_file*>(reinterpret_cast<const char*>(pc) +
                                                               host_len);
        len -= host_len;
    }

    return check_unique(paths_tmp, config, prefix) || retval;
}

void check_two(const struct fs_path_config* paths, const char* type_name, const char* prefix) {
    ASSERT_FALSE(paths == nullptr);
    ASSERT_FALSE(type_name == nullptr);
    ASSERT_FALSE(prefix == nullptr);
    bool check_internal = check_unique(paths, type_name, prefix);
    EXPECT_FALSE(check_internal);
    bool check_overrides =
        check_unique(std::string("/") + prefix + "etc/fs_config_" + type_name, prefix);
    EXPECT_FALSE(check_overrides);
}

TEST(fs_config, vendor_dirs_alias) {
    check_two(__for_testing_only__android_dirs, "dirs", "vendor/");
}

TEST(fs_config, vendor_files_alias) {
    check_two(__for_testing_only__android_files, "files", "vendor/");
}

TEST(fs_config, oem_dirs_alias) {
    check_two(__for_testing_only__android_dirs, "dirs", "oem/");
}

TEST(fs_config, oem_files_alias) {
    check_two(__for_testing_only__android_files, "files", "oem/");
}

TEST(fs_config, odm_dirs_alias) {
    check_two(__for_testing_only__android_dirs, "dirs", "odm/");
}

TEST(fs_config, odm_files_alias) {
    check_two(__for_testing_only__android_files, "files", "odm/");
}
