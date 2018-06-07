/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <inttypes.h>
#include <unistd.h>

#include <string>

#include <android-base/endian.h>
#include <android-base/unique_fd.h>

#include "crc32.h"
#include "lp/writer.h"
#include "lp_utility.h"

namespace android {
namespace fs_mgr {

static LpMetadata ToLittleEndian(const LpMetadata& metadata) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return metadata;
#else
#error "Not yet supported."
#endif
}

static std::string Serialize(const LpMetadata& input) {
    LpMetadata metadata = ToLittleEndian(input);
    LpMetadataHeader& header = metadata.header;

    // Serialize individual tables.
    std::string partitions(reinterpret_cast<const char*>(metadata.partitions.data()),
                           metadata.partitions.size() * sizeof(LpMetadataPartition));
    std::string extents(reinterpret_cast<const char*>(metadata.extents.data()),
                        metadata.extents.size() * sizeof(LpMetadataExtent));

    // Compute positions of tables.
    header.partitions.offset = 0;
    header.extents.offset = header.partitions.offset + partitions.size();
    header.tables_size = header.extents.offset + extents.size();

    // Compute payload checksum.
    std::string tables = partitions + extents;
    header.tables_checksum = CRC32(reinterpret_cast<const uint8_t*>(tables.data()), tables.size());

    // Compute header checksum.
    header.header_checksum = 0;
    header.header_checksum =
            CRC32(reinterpret_cast<const uint8_t*>(&metadata.header), sizeof(metadata.header));

    std::string header_blob =
            std::string(reinterpret_cast<const char*>(&metadata.header), sizeof(metadata.header));
    return header_blob + tables;
}

// Perform sanity checks so we don't accidentally overwrite valid metadata
// with potentially invalid metadata.
static bool ValidateMetadata(const LpMetadata& metadata, uint64_t blockdevice_size,
                             uint64_t metadata_size) {
    const LpMetadataHeader& header = metadata.header;
    // Validate the usable sector range.
    if (header.first_logical_sector > header.last_logical_sector) {
        LERROR << "Logical partition metadata has invalid sector range.";
        return false;
    }
    // Make sure we're writing within the space reserved.
    if (metadata_size > header.metadata_reserved) {
        LERROR << "Logical partition metadata is too large.";
        return false;
    }
    // Make sure the reserved region starts before the first logical sector.
    if (header.metadata_reserved > header.first_logical_sector * LP_SECTOR_SIZE) {
        LERROR << "Logical partition metadata has invalid staring sector number.";
        return false;
    }

    // Make sure the device has enough space to store two backup copies of the
    // metadata.
    uint64_t backup_size = (header.metadata_reserved + LP_METADATA_BACKUP_BLOCK_SIZE);
    uint64_t backup_space_begin = (header.last_logical_sector + 1) * LP_SECTOR_SIZE;
    if (backup_space_begin > blockdevice_size ||
        (blockdevice_size - backup_space_begin) < backup_size) {
        fprintf(stderr,
                "backup_space_begin=%" PRIu64 ", backup_size=%" PRIu64 ", bdev_size=%" PRIu64 "\n",
                backup_space_begin, backup_size, blockdevice_size);
        LERROR << "Partition is not large enough to store backup logical partition metadata.";
        return false;
    }

    // Make sure all partition entries reference valid extents.
    for (const auto& partition : metadata.partitions) {
        if (partition.first_extent_index + partition.num_extents > metadata.extents.size()) {
            LERROR << "Partition references invalid extent.";
            return false;
        }
    }

    // Make sure all linear extents have a valid range.
    for (const auto& extent : metadata.extents) {
        if (extent.target_type == LP_TARGET_TYPE_LINEAR) {
            uint64_t physical_sector = extent.target_data;
            if (physical_sector < header.first_logical_sector ||
                physical_sector + extent.num_sectors > header.last_logical_sector) {
                LERROR << "Extent table entry is out of bounds.";
                return false;
            }
        }
    }
    return true;
}

bool WritePartitionTable(const char* block_device, const LpMetadata& metadata, SyncMode sync_mode) {
    android::base::unique_fd fd(open(block_device, O_RDWR | O_SYNC));
    if (fd < 0) {
        PERROR << "open failed";
        return false;
    }

    uint64_t size;
    if (!GetDescriptorSize(fd, &size)) {
        return false;
    }

    std::string blob = Serialize(metadata);
    if (!ValidateMetadata(metadata, size, blob.size())) {
        return false;
    }

    if (sync_mode == SyncMode::Flash || sync_mode == SyncMode::Primary) {
        // Write the primary copy.
        if (!SeekFile(fd, 0, SEEK_SET) || !WriteFully(fd, blob.data(), blob.size())) {
            return false;
        }
    }
    if (sync_mode == SyncMode::Flash || sync_mode == SyncMode::Backup) {
        // Write the backup locator and backup copy.
        uint64_t backup_locator = size - LP_METADATA_BACKUP_BLOCK_SIZE;
        uint64_t backup_offset = backup_locator - metadata.header.metadata_reserved;

        LpMetadataBackupRecord locator = {htole32(LP_METADATA_HEADER_MAGIC), htole64(backup_offset)};
        if (!SeekFile(fd, backup_locator, SEEK_SET) || !WriteFully(fd, &locator, sizeof(locator))) {
            return false;
        }
        if (!SeekFile(fd, backup_offset, SEEK_SET) || !WriteFully(fd, blob.data(), blob.size())) {
            return false;
        }
    }

    return true;
}

bool WriteToFile(const char* file, const LpMetadata& input) {
    std::string blob = Serialize(input);

    FILE* fp = fopen(file, "wb");
    if (!fp) {
        PERROR << "fopen failed";
        return false;
    }
    bool ok = (fwrite(blob.data(), 1, blob.size(), fp) == blob.size());
    fclose(fp);

    if (!ok) {
        LERROR << "failed to write entire image";
        return false;
    }
    return true;
}

}  // namespace fs_mgr
}  // namespace android
