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

#include "meminfo/meminfo.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <fstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>

namespace android {
namespace meminfo {

bool ReadProcMemInfo(std::unordered_map<std::string, uint64_t>* proc_meminfo,
                     const std::string& path) {
    if (!proc_meminfo) return false;
    proc_meminfo->clear();

    std::ifstream meminfo_file{path.c_str()};
    if (!meminfo_file.is_open()) {
        PLOG(ERROR) << "Failed to open : " << path;
        return false;
    }

    for (std::string line; std::getline(meminfo_file, line);) {
        // Parse each line from /proc/meminfo which is expected to be
        // in the format "MemTotal:        XXXXXX kB" into the map of
        // { MemTotal, XXXXX }
        std::vector<std::string> pieces = ::android::base::Split(line, ":");
        if (pieces.size() != 2) {
            LOG(ERROR) << "Invalid /proc/meminfo line : " << line;
            return false;
        }

        std::vector<std::string> value =
                ::android::base::Split(::android::base::Trim(pieces[1]), " ");
        if (value.empty()) {
            LOG(ERROR) << "Invalid /proc/meminfo line : " << line;
            return false;
        }

        uint64_t size_in_kb;
        if (!::android::base::ParseUint(value[0], &size_in_kb)) {
            LOG(ERROR) << "Invalid value on /proc/meminfo line : " << line;
            return false;
        }

        // TODO: Do we really need to check for this?
        if (proc_meminfo->find(pieces[0]) != proc_meminfo->end()) {
            LOG(ERROR) << "Duplicate stat found in /proc/meminfo on line : " << line;
            return false;
        }

        proc_meminfo->emplace(std::make_pair(pieces[0], size_in_kb));
    }

    // In case the file was empty
    return !proc_meminfo->empty();
}

}  // namespace meminfo
}  // namespace android
