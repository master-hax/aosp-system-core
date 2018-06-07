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

#include "android-base/file.h"

#include "utility.h"

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
    if (!android::base::ReadFully(fd, buffer, bytes)) {
        PERROR << "read failed";
        return false;
    }
    return true;
}

bool WriteFully(int fd, const void* buffer, size_t bytes) {
    if (!android::base::WriteFully(fd, buffer, bytes)) {
        PERROR << "wrie failed";
        return false;
    }
    return true;
}

off64_t GetPrimaryMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number) {
    CHECK(slot_number < geometry.metadata_slot_count);

    off64_t offset = LP_METADATA_GEOMETRY_SIZE + geometry.metadata_max_size * slot_number;
    CHECK(offset + geometry.metadata_max_size <=
          off64_t(geometry.first_logical_sector * LP_SECTOR_SIZE));
    return offset;
}

off64_t GetBackupMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number) {
    CHECK(slot_number < geometry.metadata_slot_count);
    return off64_t(-LP_METADATA_GEOMETRY_SIZE) - off64_t(geometry.metadata_max_size * slot_number);
}

}  // namespace fs_mgr
}  // namespace android
