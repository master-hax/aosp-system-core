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

enum FbPartAttr : uint32_t {
  kAttrSystem = 1 << 0,
  kAttrBootable = 1 << 1,
  kAttrReadOnly = 1 << 2,
  kAttrHidden = 1 << 3,
  kAttrExtend = 1 << 4,
  kAttrEraseBlockAlign = 1 << 5,
};

struct PartitionHeader {
  uint64_t size;
  uint32_t attr;
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
                            part_table.partitions.size() *
                                sizeof(PartitionHeader));

  // fill up partiton table header
  PartitionTableHeader table_header;
  table_header.magic = FB_PARTITION_MAGIC;
  table_header.lun = part_table.lun;
  table_header.type = part_table.type;
  table_header.num = part_table.partitions.size();
  std::strncpy(table_header.disk_guid, part_table.disk_guid.c_str(),
               sizeof table_header.disk_guid);
  // copy the header
  std::memcpy(&data[0], &table_header, sizeof table_header);

  auto tmp =
      reinterpret_cast<PartitionHeader *>(&data[0] + sizeof table_header);
  // create serialize data for each partition
  for (auto &p : part_table.partitions) {
    PartitionHeader part_header;

    part_header.size = p.size;

    part_header.attr = 0;
    if (p.bootable) part_header.attr |= FbPartAttr::kAttrBootable;
    if (p.readonly) part_header.attr |= FbPartAttr::kAttrReadOnly;
    if (p.extend) part_header.attr |= FbPartAttr::kAttrExtend;
    if (p.erase_block_align)
      part_header.attr |= FbPartAttr::kAttrEraseBlockAlign;

    std::strncpy(part_header.name, p.name.c_str(), sizeof part_header.name);
    std::strncpy(part_header.type, p.type.c_str(), sizeof part_header.type);
    std::strncpy(part_header.guid, p.guid.c_str(), sizeof part_header.guid);
    // copy the header
    std::memcpy(tmp++, &part_header, sizeof *tmp);
  }

  return data;
}
