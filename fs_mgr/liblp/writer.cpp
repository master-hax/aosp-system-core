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

#include <android-base/unique_fd.h>

#include "crc32.h"
#include "liblp/reader.h"
#include "liblp/writer.h"
#include "utility.h"

namespace android {
namespace fs_mgr {

static std::string SerializeGeometry(const LpMetadataGeometry& input) {
    LpMetadataGeometry geometry = input;
    geometry.checksum = 0;
    geometry.checksum = CRC32(reinterpret_cast<const uint8_t*>(&geometry), sizeof(geometry));
    return std::string(reinterpret_cast<const char*>(&geometry), sizeof(geometry));
}

static bool CompareGeometry(const LpMetadataGeometry& g1, const LpMetadataGeometry& g2) {
    return g1.metadata_max_size == g2.metadata_max_size &&
           g1.metadata_slot_count == g2.metadata_slot_count &&
           g1.first_logical_sector == g2.first_logical_sector &&
           g1.last_logical_sector == g2.last_logical_sector;
}

static std::string SerializeMetadata(const LpMetadata& input) {
    LpMetadata metadata = input;
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
// with potentially invalid metadata, or random partition data with metadata.
static bool ValidateGeometryAndMetadata(const LpMetadata& metadata, uint64_t blockdevice_size,
                                        uint64_t metadata_size) {
    const LpMetadataHeader& header = metadata.header;
    const LpMetadataGeometry& geometry = metadata.geometry;
    // Validate the usable sector range.
    if (geometry.first_logical_sector > geometry.last_logical_sector) {
        LERROR << "Logical partition metadata has invalid sector range.";
        return false;
    }
    // Make sure we're writing within the space reserved.
    if (metadata_size > geometry.metadata_max_size) {
        LERROR << "Logical partition metadata is too large.";
        return false;
    }

    // Make sure the device has enough space to store two backup copies of the
    // metadata.
    uint64_t reserved_size = LP_METADATA_GEOMETRY_SIZE +
                             uint64_t(geometry.metadata_max_size) * geometry.metadata_slot_count;
    if (reserved_size < blockdevice_size ||
        reserved_size >= geometry.first_logical_sector * LP_SECTOR_SIZE) {
        LERROR << "Not enough space to store all logical partition metadata slots.";
        return false;
    }
    if (blockdevice_size - reserved_size < (geometry.last_logical_sector + 1) * LP_SECTOR_SIZE) {
        LERROR << "Not enough space to backup all logical partition metadata slots.";
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
            if (physical_sector < geometry.first_logical_sector ||
                physical_sector + extent.num_sectors > geometry.last_logical_sector) {
                LERROR << "Extent table entry is out of bounds.";
                return false;
            }
        }
    }
    return true;
}

bool WritePartitionTable(const char* block_device, const LpMetadata& metadata, SyncMode sync_mode,
                         uint32_t slot_number) {
    android::base::unique_fd fd(open(block_device, O_RDWR | O_SYNC));
    if (fd < 0) {
        PERROR << "open failed";
        return false;
    }

    uint64_t size;
    if (!GetDescriptorSize(fd, &size)) {
        return false;
    }

    const LpMetadataGeometry& geometry = metadata.geometry;
    if (sync_mode != SyncMode::Flash) {
        // Verify that the old geometry is identical. If it's not, then we've
        // based this new metadata on invalid assumptions.
        LpMetadataGeometry old_geometry;
        if (!ReadLogicalPartitionGeometry(block_device, &old_geometry)) {
            return false;
        }
        if (!CompareGeometry(geometry, old_geometry)) {
            LERROR << "Incompatible geometry in new logical partition metadata";
            return false;
        }
    }

    // Make sure we're writing to a valid metadata slot.
    if (slot_number >= geometry.metadata_slot_count) {
        LERROR << "Invalid logical partition metadata slot number.";
        return false;
    }

    // Before writing geometry and/or logical partition tables, perform some
    // basic checks that the geometry and tables are coherent, and will fit
    // on the given block device.
    std::string blob = SerializeGeometry(metadata.geometry);
    if (!ValidateGeometryAndMetadata(metadata, size, blob.size())) {
        return false;
    }

    // First write geometry if this is a flash operation. It gets written to
    // the first and last 4096-byte regions of the device.
    if (sync_mode == SyncMode::Flash) {
        std::string blob = SerializeGeometry(metadata.geometry);
        if (!SeekFile(fd, 0, SEEK_SET) || !WriteFully(fd, blob.data(), blob.size())) {
            return false;
        }
        if (!SeekFile(fd, -LP_METADATA_GEOMETRY_SIZE, SEEK_END) ||
            !WriteFully(fd, blob.data(), blob.size())) {
            return false;
        }
    }

    // Write the primary copy of the metadata.
    off64_t offset = GetPrimaryMetadataOffset(geometry, slot_number);
    if (!SeekFile(fd, offset, SEEK_SET) || !WriteFully(fd, blob.data(), blob.size())) {
        return false;
    }

    // Write the backup copy of the metadata.
    offset = lseek64(fd, GetBackupMetadataOffset(geometry, slot_number), SEEK_SET);
    if (offset == (off64_t)-1) {
        PERROR << "lseek failed";
        return false;
    }
    CHECK(offset >= off64_t((geometry.last_logical_sector + 1) * LP_SECTOR_SIZE));
    if (!WriteFully(fd, blob.data(), blob.size())) {
        return false;
    }
    return true;
}

bool WriteToImageFile(const char* file, const LpMetadata& input) {
    std::string geometry = SerializeGeometry(input.geometry);
    std::string padding(LP_METADATA_GEOMETRY_SIZE - geometry.size(), '\0');
    std::string metadata = SerializeMetadata(input);

    std::string everything = geometry + padding + metadata;

    FILE* fp = fopen(file, "wb");
    if (!fp) {
        PERROR << "fopen failed";
        return false;
    }
    bool ok = (fwrite(everything.data(), 1, everything.size(), fp) == everything.size());
    fclose(fp);

    if (!ok) {
        LERROR << "failed to write entire image";
        return false;
    }
    return true;
}

}  // namespace fs_mgr
}  // namespace android
