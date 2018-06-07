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

#include "lp/reader.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <functional>

#include <android-base/endian.h>
#include <android-base/unique_fd.h>

#include "crc32.h"
#include "lp_utility.h"

namespace android {
namespace fs_mgr {

static void FixEndianness(LpMetadataTableDescriptor& desc) {
    desc.offset = le32toh(desc.offset);
    desc.num_entries = le32toh(desc.num_entries);
    desc.entry_size = le32toh(desc.entry_size);
}

static bool ValidateTableBounds(const LpMetadataHeader& header,
                                const LpMetadataTableDescriptor& table) {
    if (table.offset > header.tables_size) {
        return false;
    }
    uint64_t table_size = uint64_t(table.num_entries) * table.entry_size;
    if (header.tables_size - table.offset < table_size) {
        return false;
    }
    return true;
}

static bool ParseAndValidateMetadataHeader(LpMetadataHeader& header) {
    // To compute the header's checksum, we have to temporarily set its checksum
    // field to 0.
    LpMetadataHeader tmp = header;
    tmp.header_checksum = 0;

    uint32_t expected_checksum = CRC32(reinterpret_cast<const uint8_t*>(&tmp), sizeof(tmp));
    if (expected_checksum != le32toh(header.header_checksum)) {
        LERROR << "Logical partition metadata has invalid checksum.";
        return false;
    }

    // Rewrite the header to be in host byte order.
    header.magic = le32toh(header.magic);
    header.major_version = le16toh(header.major_version);
    header.minor_version = le16toh(header.minor_version);
    header.header_size = le32toh(header.header_size);
    header.header_checksum = le32toh(header.header_checksum);
    header.tables_size = le32toh(header.tables_size);
    header.tables_checksum = le32toh(header.tables_checksum);
    header.first_logical_sector = le64toh(header.first_logical_sector);
    header.last_logical_sector = le64toh(header.last_logical_sector);
    header.metadata_reserved = le32toh(header.metadata_reserved);
    FixEndianness(header.partitions);
    FixEndianness(header.extents);

    // Do basic validation of key metadata bits.
    if (header.magic != LP_METADATA_HEADER_MAGIC) {
        LERROR << "Logical partition metadata has invalid magic value.";
        return false;
    }
    // Check that the version is compatible.
    if (header.major_version != LP_METADATA_MAJOR_VERSION ||
        header.minor_version > LP_METADATA_MINOR_VERSION) {
        LERROR << "Logical partition metadata has incompatible version.";
        return false;
    }
    if (!ValidateTableBounds(header, header.partitions) ||
        !ValidateTableBounds(header, header.extents)) {
        LERROR << "Logical partition metadata has invalid table bounds.";
        return false;
    }
    // Check that table entry sizes can accomodate their respective structs. If
    // table sizes change, these checks will have to be adjusted.
    if (header.partitions.entry_size < sizeof(LpMetadataPartition)) {
        LERROR << "Logical partition metadata has invalid partition table entry size.";
        return false;
    }
    if (header.extents.entry_size < sizeof(LpMetadataExtent)) {
        LERROR << "Logical partition metadata has invalid extent table entry size.";
        return false;
    }
    return true;
}

typedef std::function<bool(void* buffer, size_t num_bytes)> ReadMetadataFn;

// Parse and validate all metadata given a function that reads into a buffer.
// The read operation assumes a sequential stream, and should only return true
// if |num_bytes| could be read.
static std::unique_ptr<LpMetadata> ParseMetadata(const ReadMetadataFn& read_fn) {
    // First read and validate the header.
    std::unique_ptr<LpMetadata> metadata = std::make_unique<LpMetadata>();
    if (!read_fn(&metadata->header, sizeof(metadata->header))) {
        return nullptr;
    }
    if (!ParseAndValidateMetadataHeader(metadata->header)) {
        return nullptr;
    }

    LpMetadataHeader& header = metadata->header;

    // Read the metadata payload. Allocation is fallible in case the metadata is
    // corrupt and has some huge value.
    std::unique_ptr<uint8_t[]> buffer(new (std::nothrow) uint8_t[header.tables_size]);
    if (!buffer) {
        LERROR << "Out of memory reading logical partition tables.";
        return nullptr;
    }
    if (!read_fn(buffer.get(), header.tables_size)) {
        return nullptr;
    }

    uint32_t tables_checksum = CRC32(buffer.get(), header.tables_size);
    if (tables_checksum != header.tables_checksum) {
        LERROR << "Logical partition metadata has invalid table checksum.";
        return nullptr;
    }

    // ValidateTableSize ensure that |cursor| will be valid for the number of
    // entry in the table.
    uint8_t* cursor = buffer.get() + header.partitions.offset;
    for (size_t i = 0; i < header.partitions.num_entries; i++) {
        LpMetadataPartition partition;
        memcpy(&partition, cursor, sizeof(partition));
        cursor += header.partitions.entry_size;

        partition.attributes = le32toh(partition.attributes);
        if (partition.attributes & ~LP_PARTITION_ATTRIBUTE_MASK) {
            LERROR << "Logical partition has invalid attribute set.";
            return nullptr;
        }

        partition.first_extent_index = le32toh(partition.first_extent_index);
        partition.num_extents = le32toh(partition.num_extents);
        if (partition.first_extent_index + partition.num_extents > header.extents.num_entries) {
            LERROR << "Logical partition has invalid extent list.";
            return nullptr;
        }

        metadata->partitions.push_back(partition);
    }

    cursor = buffer.get() + header.extents.offset;
    for (size_t i = 0; i < header.extents.num_entries; i++) {
        LpMetadataExtent extent;
        memcpy(&extent, cursor, sizeof(extent));
        cursor += header.extents.entry_size;

        extent.num_sectors = le64toh(extent.num_sectors);
        extent.target_type = le32toh(extent.target_type);
        extent.target_data = le64toh(extent.target_data);
        metadata->extents.push_back(extent);
    }

    return metadata;
}

std::unique_ptr<LpMetadata> ParseMetadata(const void* buffer, size_t buffer_size) {
    const uint8_t* cursor = reinterpret_cast<const uint8_t*>(buffer);
    const uint8_t* end = cursor + buffer_size;
    auto reader = [&cursor, end](void* out, size_t bytes) -> bool {
        if (size_t(end - cursor) < bytes) {
            LERROR << "Attempted to read past end of buffer.";
            return false;
        }
        memcpy(out, cursor, bytes);
        cursor += bytes;
        return true;
    };
    return ParseMetadata(reader);
}

std::unique_ptr<LpMetadata> ReadMetadata(const char* block_device) {
    android::base::unique_fd fd(open(block_device, O_RDONLY));
    if (fd < 0) {
        PERROR << "open failed";
        return nullptr;
    }

    auto fn = [&fd](void* buffer, size_t num_bytes) -> bool {
        return ReadFully(fd, buffer, num_bytes);
    };
    std::unique_ptr<LpMetadata> metadata = ParseMetadata(fn);
    if (metadata) {
        return metadata;
    }

    // Try to read the backup copy.
    LpMetadataBackupRecord record;
    if (!SeekFile(fd, -LP_METADATA_BACKUP_BLOCK_SIZE, SEEK_END)) {
        return nullptr;
    }
    if (!ReadFully(fd, &record, sizeof(record))) {
        return nullptr;
    }

    record.magic = le32toh(record.magic);
    record.metadata_location = le32toh(record.metadata_location);
    if (record.magic != LP_METADATA_HEADER_MAGIC) {
        LERROR << "Backup contains invalid metadata signature.";
        return nullptr;
    }
    if (!SeekFile(fd, record.metadata_location, SEEK_SET)) {
        return nullptr;
    }
    return ParseMetadata(fn);
}

static std::string NameFromFixedArray(const char* name, size_t buffer_size) {
    // If the end of the buffer has a null character, it's safe to assume the
    // buffer is null terminated. Otherwise, we cap the string to the input
    // buffer size.
    if (name[buffer_size - 1] == '\0') {
        return std::string(name);
    }
    return std::string(name, buffer_size);
}

std::string GetPartitionName(const LpMetadataPartition& partition) {
    return NameFromFixedArray(partition.name, sizeof(partition.name));
}

}  // namespace fs_mgr
}  // namespace android
