/*
 * Copyright (C) 2019 The Android Open Source Project
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

/* This .h file is intended for C clients (usually bootloader).  */

#pragma once

#include <stdint.h>

/* Magic signature for VBMetaTable. */
#define VBMETA_TABLE_MAGIC 0x61766266

/* Current vbmeta table version. */
#define VBMETA_TABLE_MAJOR_VERSION 1
#define VBMETA_TABLE_MINOR_VERSION 0

/* VBMeta Table size. */
#define VBMETA_TABLE_HEADER_SIZE sizeof(VBMetaTableHeader)
#define VBMETA_TABLE_DESCRIPTOR_SIZE sizeof(VBMetaDescriptor)
#define VBMETA_TABLE_MAX_SIZE 2048

/* VBMeta Table offset. */
#define PRIMARY_VBMETA_TABLE_OFFSET 0
#define BACKUP_VBMETA_TABLE_OFFSET 2048

/* Binary format of the vbmeta table image.
 *
 * The vbmeta table image consists of two blocks:
 *
 *  +-----------------------------------------+
 *  | Header data - fixed size                |
 *  +-----------------------------------------+
 *  | VBMeta descriptors - variable size      |
 *  +-----------------------------------------+
 *
 * The "Header data" block is described by the following struct and
 * is always 128 bytes long.
 *
 * The "VBMeta descriptor" is |descriptors_size| + |partition_name_length|
 * bytes long. It contains the physical offset and size for each chained
 * VBMeta in the super partition and is followed by |partition_name_length|
 * bytes of the partition name (UTF-8 encoded).
 *
 */

typedef struct VBMetaTableHeader {
    /*  0: Magic signature (VBMETA_TABLE_MAGIC). */
    uint32_t magic;

    /*  4: Major version. Version number required to read this vbmeta table. If the version is not
     * equal to the library version, the vbmeta table should be considered incompatible.
     */
    uint16_t major_version;

    /*  6: Minor version. A library supporting newer features should be able to
     * read vbmeta table with an older minor version. However, an older library
     * should not support reading vbmeta table if its minor version is higher.
     */
    uint16_t minor_version;

    /*  8: The size of this header struct. */
    uint32_t header_size;

    /*  12: The size of this vbmeta table. */
    uint32_t total_size;

    /*  16: SHA256 checksum of this vbmeta table, with this field set to 0. */
    uint8_t checksum[32];

    /*  48: The size of this vbmeta table descriptors. */
    uint32_t descriptors_size;

    /* 52: reserved for other usage, filled with 0. */
    uint8_t reserved[76];
} __attribute__((packed)) VBMetaTableHeader;

typedef struct VBMetaDescriptor {
    /*  0: The physical offset of the partition's vbmeta. */
    uint64_t vbmeta_offset;

    /*  8: The size of the partition's vbmeta. */
    uint32_t vbmeta_size;

    /*  12: The length of the partition's name. */
    uint32_t partition_name_length;

    /*  16: Space reserved for other usage, filled with 0. */
    uint8_t reserved[48];
} __attribute__((packed)) VBMetaDescriptor;