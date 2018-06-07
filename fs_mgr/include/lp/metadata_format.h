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

#ifndef LOGICAL_PARTITION_METADATA_FORMAT_H_
#define LOGICAL_PARTITION_METADATA_FORMAT_H_

#ifdef __cplusplus
#include <string>
#include <vector>
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic of the logical partition metadata header. */
#define LP_METADATA_HEADER_MAGIC 0x414C5030

/* Current metadata version. */
#define LP_METADATA_MAJOR_VERSION 1
#define LP_METADATA_MINOR_VERSION 0

/* Attributes for the LpMetadataPartition::attributes field.
 *
 * READONLY - The partition should not be considered writable. When used with
 * device mapper, the block device will be created as read-only.
 */
#define LP_PARTITION_ATTR_READONLY 0x1

/* Mask that defines all valid attributes. */
#define LP_PARTITION_ATTRIBUTE_MASK (LP_PARTITION_ATTR_READONLY)

/* Default name of the physical partition that holds logical partition entries.
 * The layout of this partition will look like:
 *
 *     +--------------------+
 *     | Primary metadata   |
 *     +--------------------+
 *     | Logical partitions |
 *     +--------------------+
 *     | Backup metadata    |
 *     +--------------------+
 *     | Backup locator     |
 *     +--------------------+
 */
#define LP_METADATA_PARTITION_NAME "android"

/* Size of a sector is always 512 bytes for compatibility with the Linux kernel. */
#define LP_SECTOR_SIZE 512

/* The logical partition metadata has a number of tables; they are described
 * in the header via the following structure.
 *
 * The size of the table can be computed by multiplying entry_size by
 * num_entries, and the result must not overflow a 32-bit signed integer.
 */
typedef struct LpMetadataTableDescriptor {
    /*  0: Location of the table, relative to the metadata header. */
    uint32_t offset;
    /*  4: Number of entries in the table. */
    uint32_t num_entries;
    /*  8: Size of each entry in the table, in bytes. */
    uint32_t entry_size;
} __attribute__((packed)) LpMetadataTableDescriptor;

/* Binary format for the header of the logical partition metadata format.
 *
 * The format has three sections. The header must occur first, and the
 * proceeding tables may be placed in any order after.
 *
 *  +-----------------------------------------+
 *  | Header data - fixed size                |
 *  +-----------------------------------------+
 *  | Partition table - variable size         |
 *  +-----------------------------------------+
 *  | Partition table extents - variable size |
 *  +-----------------------------------------+
 *
 * The "Header" portion is described by LpMetadataHeader. It will always
 * precede the other three blocks.
 *
 * All fields are stored in little-endian byte order when serialized.
 *
 * This struct is versioned; see the |major_version| and |minor_version|
 * fields.
 */
typedef struct LpMetadataHeader {
    /*  0: Four bytes equal to LP_METADATA_HEADER_MAGIC. */
    uint32_t magic;

    /*  4: Version number required to read this metadata. If the version is not
     * equal to the library version, the metadata should be considered
     * incompatible.
     */
    uint16_t major_version;

    /*  6: Minor version. A library supporting newer features should be able to
     * read metadata with an older minor version. However, an older library
     * should not support reading metadata if its minor version is higher.
     */
    uint16_t minor_version;

    /*  8: The size of this header struct. */
    uint32_t header_size;

    /* 12: CRC32 checksum of the header, up to |header_size| bytes, computed as
     * if this field were set to 0.
     */
    uint32_t header_checksum;

    /* 16: The total size of all tables. This size is contiguous; tables may not
     * have gaps in between, and they immediately follow the header.
     */
    uint32_t tables_size;

    /* 20: CRC32 checksum of all table contents. */
    uint32_t tables_checksum;

    /* 24: First usable sector for allocating logical partitions. */
    uint64_t first_logical_sector;
    /* 32: Last usable sector, inclusive, for allocating logical partitions. */
    uint64_t last_logical_sector;

    /* 36: Maximum size of the metadata blob. This is the minimum space that
     * must be reserved before |first_logical_sector|.
     */
    uint32_t metadata_reserved;

    /* 40: Partition table descriptor. */
    LpMetadataTableDescriptor partitions;
    /* 52: Extent table descriptor. */
    LpMetadataTableDescriptor extents;
} __attribute__((packed)) LpMetadataHeader;

/* This struct defines a logical partition entry, similar to what would be
 * present in a GUID Partition Table.
 */
typedef struct LpMetadataPartition {
    /*  0: Name of this partition in ASCII characters. Any unused characters in
     * the buffer must be set to 0. Characters may only be alphanumeric or _.
     * The name must include at least one ASCII character, and it must be unique
     * across all partition names. The length (36) is the same as the maximum
     * length of a GPT partition name.
     */
    char name[36];

    /* 36: Globally unique identifier (GUID) of this partition. */
    uint8_t guid[16];

    /* 52: Attributes for the partition (see LP_PARTITION_ATTR_* flags above). */
    uint32_t attributes;

    /* 56: Index of the first extent owned by this partition. The extent will
     * start at logical sector 0. Gaps between extents are not allowed.
     */
    uint32_t first_extent_index;

    /* 60: Number of extents in the partition. Every partition must have at
     * least one extent.
     */
    uint32_t num_extents;
} __attribute__((packed)) LpMetadataPartition;

/* This extent is a dm-linear target, and the index is an index into the
 * LinearExtent table.
 */
#define LP_TARGET_TYPE_LINEAR 0

/* This extent is a dm-zero target. The index is ignored and must be 0. */
#define LP_TARGET_TYPE_ZERO 1

/* This struct defines an extent entry in the extent table block. */
typedef struct LpMetadataExtent {
    /*  0: Length of this extent, in 512-byte sectors. */
    uint64_t num_sectors;

    /*  8: Target type for device-mapper (see LP_TARGET_TYPE_* values). */
    uint32_t target_type;

    /* 12: Contents depends on target_type.
     *
     * LINEAR: The sector on the physical partition that this extent maps onto.
     * ZERO: This field must be 0.
     */
    uint64_t target_data;
} __attribute__((packed)) LpMetadataExtent;

/* A backup copy of the metadata is stored at the very end of the block
 * device. However, we don't necessarily know how to find it, because
 * the blob is variably sized. To address this, we reserve a 4KB block
 * at the very end of the physical partition. This blocks stores a very
 * simple locator record to identify where the backup is.
 */
#define LP_METADATA_BACKUP_BLOCK_SIZE 4096

typedef struct LpMetadataBackupRecord {
    /* 0: Magic signature (LP_METADATA_HEADER_MAGIC). */
    uint32_t magic;

    /* 4: Absolute location of the metadata blob. */
    uint64_t metadata_location;
} __attribute__((packed)) LpMetadataBackupRecord;

#ifdef __cplusplus
} /* extern "C" */
#endif

#ifdef __cplusplus
namespace android {
namespace fs_mgr {

// Helper structure for easily interpreting deserialized metadata, or
// re-serializing metadata.
struct LpMetadata {
    LpMetadataHeader header;
    std::vector<LpMetadataPartition> partitions;
    std::vector<LpMetadataExtent> extents;
};

// Helper to extract a safe C++ strings containing the partition name.
std::string GetPartitionName(const LpMetadataPartition& partition);

}  // namespace fs_mgr
}  // namespace android
#endif

#endif /* LOGICAL_PARTITION_METADATA_FORMAT_H_ */
