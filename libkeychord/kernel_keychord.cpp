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

// keychord driver interface

#define LOG_TAG "kernel_keychord"
#include "kernel_keychord.h"

#include <keychord/keychord.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/keychord.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <unistd.h>

#include <vector>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include "libkeychord.h"

namespace {

constexpr char KeychordDevice[] = "/dev/keychord";

std::string format(uint16_t val) {
    return android::base::StringPrintf("0x%04" PRIx16, val);
}

std::string format(std::vector<uint16_t> vec) {
    std::string ret("{");
    bool prefix = false;
    for (auto& v : vec) {
        if (prefix) ret += ',';
        ret += format(v);
        prefix = true;
    }
    ret += '}';
    return ret;
}

}  // namespace

LIBKEYCHORD_HIDDEN int KeychordKernelInit() {
    auto keychord_fd = TEMP_FAILURE_RETRY(::open(KeychordDevice, O_RDWR | O_CLOEXEC));
    if (keychord_fd == -1) PLOG(ERROR) << "could not open " << KeychordDevice;
    return keychord_fd;
}

LIBKEYCHORD_HIDDEN void KeychordKernelRelease(int keychord_fd) {
    ::close(keychord_fd);
}

// NEED TO ITERATE and generate scatter-gather to writev
LIBKEYCHORD_HIDDEN int KeychordKernelEnable(int keychord_fd) {
    if (KeychordEntries.empty()) return 0;
    if (keychord_fd < 0) {
        errno = EBADF;
        return -1;
    }

    std::vector<uint16_t> buffer;

    for (auto& e : KeychordEntries) {
        if (!e.second.valid()) continue;
        if (e.second.getType() != EV_KEY) continue;
        buffer.push_back(KEYCHORD_VERSION);
        buffer.push_back(e.first);
        buffer.push_back(e.second.getKeycodes().size());
        for (auto& c : e.second.getKeycodes()) {
            buffer.push_back(c);
        }
    }
    size_t totalsize = buffer.size() * sizeof(uint16_t);
    if (totalsize == 0) {
        errno = EINVAL;
        return -1;
    }
    LOG(VERBOSE) << "pwrite(" << keychord_fd << "," << format(buffer) << "," << totalsize
                 << ",0)==" << totalsize;
    auto ret = pwrite(keychord_fd, buffer.data(), totalsize, 0);
    if (ret != totalsize) {
        PLOG(ERROR) << "could not configure " << KeychordDevice << " " << ret << " != " << totalsize;
    }
    return ret;
}
