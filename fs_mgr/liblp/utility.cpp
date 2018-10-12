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
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <android-base/file.h>
#include <ext4_utils/ext4_utils.h>
#include <openssl/sha.h>

#include "utility.h"

namespace android {
namespace fs_mgr {

bool GetDescriptorSize(int fd, uint64_t* size) {
    struct stat s;
    if (fstat(fd, &s) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "fstat failed";
        return false;
    }

    if (S_ISBLK(s.st_mode)) {
        *size = get_block_device_size(fd);
        return *size != 0;
    }

    int64_t result = SeekFile64(fd, 0, SEEK_END);
    if (result == -1) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed";
        return false;
    }

    *size = result;
    return true;
}

int64_t SeekFile64(int fd, int64_t offset, int whence) {
    static_assert(sizeof(off_t) == sizeof(int64_t), "Need 64-bit lseek");
    return lseek(fd, offset, whence);
}

int64_t GetPrimaryGeometryOffset() {
    return LP_PARTITION_RESERVED_BYTES;
}

int64_t GetBackupGeometryOffset() {
    return GetPrimaryGeometryOffset() + LP_METADATA_GEOMETRY_SIZE;
}

int64_t GetPrimaryMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number) {
    CHECK(slot_number < geometry.metadata_slot_count);
    int64_t offset = LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2) +
                     geometry.metadata_max_size * slot_number;
    return offset;
}

int64_t GetBackupMetadataOffset(const LpMetadataGeometry& geometry, uint32_t slot_number) {
    CHECK(slot_number < geometry.metadata_slot_count);
    int64_t start = LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2) +
                    int64_t(geometry.metadata_max_size) * geometry.metadata_slot_count;
    return start + int64_t(geometry.metadata_max_size * slot_number);
}

uint64_t GetTotalMetadataSize(uint32_t metadata_max_size, uint32_t max_slots) {
    return LP_PARTITION_RESERVED_BYTES +
           (LP_METADATA_GEOMETRY_SIZE + metadata_max_size * max_slots) * 2;
}

const LpMetadataBlockDevice* GetMetadataSuperBlockDevice(const LpMetadata& metadata) {
    if (metadata.block_devices.empty()) {
        return nullptr;
    }
    return &metadata.block_devices[0];
}

void SHA256(const void* data, size_t length, uint8_t out[32]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, length);
    SHA256_Final(out, &c);
}

uint32_t SlotNumberForSlotSuffix(const std::string& suffix) {
    if (suffix.empty()) {
        return 0;
    }
    if (suffix.size() != 2 || suffix[0] != '_' || suffix[1] < 'a') {
        LERROR << __PRETTY_FUNCTION__ << "slot '" << suffix
               << "' does not have a recognized format.";
        return 0;
    }
    return suffix[1] - 'a';
}

uint64_t GetTotalSuperPartitionSize(const LpMetadata& metadata) {
    uint64_t size = 0;
    for (const auto& block_device : metadata.block_devices) {
        size += block_device.size;
    }
    return size;
}

}  // namespace fs_mgr
}  // namespace android
