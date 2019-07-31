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

#pragma once

#ifdef __cplusplus
#include <vector>
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic signature for SuperVBMeta. */
#define SUPER_VBMETA_MAGIC 0x61766266

/* Current metadata version. */
#define SUPER_VBMETA_MAJOR_VERSION 1
#define SUPER_VBMETA_MINOR_VERSION 0

/* SuperVBMeta size */
#define SUPER_VBMETA_HEADER_SIZE 52
#define SUPER_VBMETA_DESCRIPTOR_SIZE 64
#define SUPER_VBMETA_TOTAL_SIZE 4096

struct SuperVBMetaHeader {
    uint32_t magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t header_size;
    uint32_t total_size;
    uint8_t checksum[32];
    uint32_t descriptors_size;
} __attribute__((packed));

struct SuperVBMetaDescriptor {
    uint64_t vbmeta_offset;
    uint32_t vbmeta_size;
    uint32_t partition_name_length;
    uint8_t reserved[48];
    char* partition_name;
} __attribute__((packed));

struct SuperVBMeta {
    SuperVBMetaHeader header;
    std::vector<SuperVBMetaDescriptor> descriptors;
};

#ifdef __cplusplus
} /* extern "C" */
#endif