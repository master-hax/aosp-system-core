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

#ifndef PARTITION_H_
#define PARTITION_H_

#define FB_PARTITION_MAGIC  0x54504246 //"FBPT" (FastBoot Partition Table)

#define GPT_ATTR_SYSTEM     1
#define GPT_ATTR_BOOTABLE   (1ULL << 2)
#define GPT_ATTR_RO         (1ULL << 60)
#define GPT_ATTR_HIDDEN     (1ULL << 62)

enum partition_type : uint32_t {
  PARTITION_TYPE_NONE = 0,
  PARTITION_TYPE_GPT = 1,
  PARTITION_TYPE_UNKNOWN = 0xffffffff,
};

class partition {
 public:
  partition(const char **attr);
 private:
  uint64_t size;
  uint64_t attr;
  uint32_t extend;
  char name[36];
  char type[37];
  char guid[37];
  char padding[2];
} __attribute__((__packed__));

class partition_table {
 public:
  static int current_lun;
  partition_table(const char **attr);
  void add_partition(partition p);
  uint32_t get_lun() { return lun; };
  partition_type get_type() { return type; };
  std::vector<uint8_t> serialize();
 private:
  struct {
    uint32_t magic;
    uint32_t lun;
    partition_type type;
    uint32_t num;
    char disk_guid[37];
    char padding[3];
  } __attribute__((__packed__));
  std::vector<partition> partitions;
};

partition_table **get_partition_table(const std::string fname);
void free_partition_table(partition_table **pt);

class storage_info {
 public:
  storage_info(std::string);
  std::vector<partition_table>& get_partition_tables() { return tables; };
  void add_partition_table(partition_table table);
  partition_table& get_last_partition_table() { return tables.back(); };
 private:
  std::vector<partition_table> tables;
};

#endif /* PARTITION_H_ */
