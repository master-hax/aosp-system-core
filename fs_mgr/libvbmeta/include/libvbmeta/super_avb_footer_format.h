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

#ifndef SUPER_AVB_FOOTER_FORMAT_H_
#define SUPER_AVB_FOOTER_FORMAT_H_

#ifdef __cplusplus
#include <string>
#include <vector>
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic signature for SuperAVBFooter. */
#define SUPER_AVB_FOOTER_MAGIC 0x61766266

/* Current metadata version. */
#define SUPER_AVB_FOOTER_MAJOR_VERSION 1
#define SUPER_AVB_FOOTER_MINOR_VERSION 0

/* super avb footer size */
#define SUPER_AVB_FOOTER_HEADER_SIZE 52
#define SUPER_AVB_FOOTER_DESCRIPTOR_SIZE 64
#define SUPER_FOOTER_TOTAL_SIZE 4096

struct SuperAVBFooterHeader {
  uint32_t magic;
  uint16_t major_version;
  uint16_t minor_version;
  uint32_t header_size;
  uint32_t total_size;
  uint8_t checksum[32];
  uint32_t descriptors_size;
} __attribute__((packed));

struct VBMetaDescriptor {
  uint64_t vbmeta_offset;
  uint32_t vbmeta_size;
  uint32_t partition_name_length;
  uint8_t reserved[48];
  char *partition_name;
} __attribute__((packed));

struct SuperAVBFooter {
  SuperAVBFooterHeader header;
  std::vector<VBMetaDescriptor> descriptors;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SUPER_AVB_FOOTER_FORMAT_H_ */