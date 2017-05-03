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

static bool check_unique(const struct fs_path_config* paths, const char* name,
                         const std::string& prefix) {
    bool retval = false;

    std::string alternate = "system/" + prefix;

    bool no_end = false;
    static constexpr size_t max_idx = 4096;

    for (size_t second, idx = 0; paths[idx].prefix; ++idx) {
        if (idx > max_idx) {
            no_end = true;
            break;
        }
        std::string path(paths[idx].prefix);
        if (android::base::StartsWith(path, prefix.c_str())) {
            path = alternate + path.substr(prefix.length());
            for (second = 0; paths[second].prefix; ++second) {
                if (second > max_idx) {
                    no_end = true;
                    break;
                }
                if (path == paths[second].prefix) {
                    GTEST_LOG_(ERROR)
                        << "duplicate alias paths in system/core/libcutils/fs_config.cpp:android_"
                        << name << "[]: " << paths[idx].prefix << " and " << paths[second].prefix
                        << " (remove later)";
                    retval = true;
                    break;
                }
            }
        } else if (android::base::StartsWith(path, alternate.c_str())) {
            path = prefix + path.substr(alternate.length());
            for (second = 0; paths[second].prefix; ++second) {
                if (second > max_idx) {
                    no_end = true;
                    break;
                }
                if (path == paths[second].prefix) break;
            }
            if (!paths[second].prefix) {
                GTEST_LOG_(ERROR) << "replace path in system/core/libcutils/fs_config.cpp:android_"
                                  << name << "[]: " << paths[idx].prefix << " with " << path;
                retval = true;
            }
        }
    }
    if (no_end) {
        GTEST_LOG_(WARNING) << "system/core/libcutils/fs_config.cpp:android_" << name
                            << "[]: has no end (missing null prefix)";
        retval = true;
    }
    return retval;
}

static bool check_unique(const std::string& config, const std::string& prefix) {
    int retval = false;

    std::string data;
    if (!android::base::ReadFileToString(config, &data)) return retval;

    const struct fs_path_config_from_file* pc =
        reinterpret_cast<const fs_path_config_from_file*>(data.c_str());
    size_t len = data.size();

    std::string alternate = "system/" + prefix;
    while (len > 0) {
        uint16_t host_len = pc->len;
        if (host_len > len) {
            GTEST_LOG_(WARNING) << config << " corrupted";
            retval = true;
            break;
        }

        std::string path(pc->prefix);

        const struct fs_path_config_from_file* pc_second =
            reinterpret_cast<const fs_path_config_from_file*>(data.c_str());
        size_t len_second = data.size();

        if (android::base::StartsWith(path, prefix.c_str())) {
            path = alternate + path.substr(prefix.length());
            while (len_second > 0) {
                uint16_t host_len_second = pc->len;
                if (host_len_second > len_second) break;

                if (path == pc_second->prefix) {
                    GTEST_LOG_(ERROR) << "duplicate alias paths in " << config << ": " << pc->prefix
                                      << " and " << pc_second->prefix << " (remove later)";
                    retval = true;
                    break;
                }
                pc_second = reinterpret_cast<const fs_path_config_from_file*>(
                    reinterpret_cast<const char*>(pc_second) + host_len_second);
                len_second -= host_len_second;
            }
        } else if (android::base::StartsWith(path, alternate.c_str())) {
            path = prefix + path.substr(alternate.length());
            while (len_second > 0) {
                uint16_t host_len_second = pc->len;
                if (host_len_second > len_second) {
                    len_second = 0;
                    break;
                }

                if (path == pc_second->prefix) break;
                pc_second = reinterpret_cast<const fs_path_config_from_file*>(
                    reinterpret_cast<const char*>(pc_second) + host_len_second);
                len_second -= host_len_second;
            }
            if (len_second <= 0) {
                GTEST_LOG_(ERROR) << "replace path in " << config << ": " << pc->prefix << " with "
                                  << path;
                retval = true;
            }
        }

        pc = reinterpret_cast<const fs_path_config_from_file*>(reinterpret_cast<const char*>(pc) +
                                                               host_len);
        len -= host_len;
    }
    return retval;
}

void check_two(const struct fs_path_config* paths, const char* name, const char* prefix) {
    ASSERT_FALSE(paths == nullptr);
    ASSERT_FALSE(name == nullptr);
    ASSERT_FALSE(prefix == nullptr);
    bool check_internal = check_unique(paths, name, prefix);
    EXPECT_FALSE(check_internal);
    bool check_overrides = check_unique(std::string("/") + prefix + "etc/fs_config_" + name, prefix);
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
