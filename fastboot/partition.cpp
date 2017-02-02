/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "partition.h"
#include <storage_info.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#define FB_PARTITION_MAGIC 0x54504246  //"FBPT" (FastBoot Partition Table)

#define GPT_ATTR_SYSTEM 1
#define GPT_ATTR_BOOTABLE (1ULL << 2)
#define GPT_ATTR_RO (1ULL << 60)
#define GPT_ATTR_HIDDEN (1ULL << 62)

struct PartitionHeader {
  uint64_t size;
  uint64_t attr;
  uint32_t extend;
  uint32_t erase_block_align;
  char name[36];
  char type[37];
  char guid[37];
  char padding[2];
} __attribute__((__packed__));

struct PartitionTableHeader {
  uint32_t magic;
  uint32_t version{1};
  uint32_t lun;
  PartitionType type;
  uint32_t num;
  char disk_guid[37];
  char padding[3];
} __attribute__((__packed__)) header_;

std::vector<uint8_t> fastboot_partition_table_data(
    const PartitionTable &part_table) {
  std::vector<uint8_t> data(sizeof(PartitionTableHeader) +
                            part_table.GetNumOfPartitions() *
                                sizeof(PartitionHeader));

  // fill up partiton table header
  PartitionTableHeader table_header;
  table_header.magic = FB_PARTITION_MAGIC;
  table_header.lun = part_table.GetLun();
  table_header.type = part_table.GetType();
  table_header.num = part_table.GetNumOfPartitions();
  std::strncpy(table_header.disk_guid, part_table.GetDiskGuid().c_str(),
               sizeof table_header.disk_guid);
  // copy the header
  std::memcpy(&data[0], &table_header, sizeof table_header);

  auto tmp =
      reinterpret_cast<PartitionHeader *>(&data[0] + sizeof table_header);
  // create serialize data for each partition
  for (auto &p : part_table.GetPartitions()) {
    PartitionHeader part_header;

    part_header.size = p.GetSize();
    if (p.IsExtended()) part_header.extend = 1;

    part_header.attr = 0;
    if (p.IsBootable()) part_header.attr |= GPT_ATTR_BOOTABLE;
    if (p.IsReadOnly()) part_header.attr |= GPT_ATTR_RO;

    part_header.erase_block_align = p.IsEraseBlockSizeAligned() ? 1 : 0;

    std::strncpy(part_header.name, p.GetName().c_str(),
                 sizeof part_header.name);
    std::strncpy(part_header.type, p.GetType().c_str(),
                 sizeof part_header.type);
    std::strncpy(part_header.guid, p.GetGuid().c_str(),
                 sizeof part_header.guid);
    // copy the header
    std::memcpy(tmp++, &part_header, sizeof *tmp);
  }

  return data;
}
