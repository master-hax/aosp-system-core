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
#include <linux/fs.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lp_utility.h"

namespace android {
namespace fs_mgr {

bool GetDescriptorSize(int fd, uint64_t* size) {
    struct stat s;
    if (fstat(fd, &s) < 0) {
        PERROR << "fstat failed";
        return false;
    }

    if (S_ISBLK(s.st_mode)) {
        if (ioctl(fd, BLKGETSIZE64, size) != -1) {
            return true;
        }
    }

    off64_t result = lseek64(fd, 0, SEEK_END);
    if (result == (off64_t)-1) {
        PERROR << "lseek64 failed";
        return false;
    }

    *size = result;
    return true;
}

bool SeekFile(int fd, off64_t offset, int whence) {
    if (lseek64(fd, offset, whence) == (off64_t)-1) {
        PERROR << "lseek64 failed";
        return false;
    }
    return true;
}

bool ReadFully(int fd, void* buffer, size_t bytes) {
    uint8_t* pos = reinterpret_cast<uint8_t*>(buffer);
    size_t remaining = bytes;
    while (remaining) {
        ssize_t rv = TEMP_FAILURE_RETRY(read(fd, pos, remaining));
        if (rv == -1) {
            PERROR << "read failed";
            return false;
        }
        remaining -= size_t(rv);
        pos += size_t(rv);
    }
    return true;
}

bool WriteFully(int fd, const void* buffer, size_t bytes) {
    const uint8_t* pos = reinterpret_cast<const uint8_t*>(buffer);
    size_t remaining = bytes;
    while (remaining) {
        ssize_t rv = TEMP_FAILURE_RETRY(write(fd, pos, remaining));
        if (rv == -1) {
            PERROR << "write failed";
            return false;
        }
        remaining -= size_t(rv);
        pos += size_t(rv);
    }
    return true;
}

}  // namespace fs_mgr
}  // namespace android
