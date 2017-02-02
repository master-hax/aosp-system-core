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

#ifndef _PARTITION_H_
#define _PARTITION_H_

enum partition_type : uint32_t {
  PARTITION_TYPE_NONE = 0,
  PARTITION_TYPE_GPT = 1,
  PARTITION_TYPE_UNKNOWN = 0xffffffff,
};

class partition {
 public:
  partition(const char **attr);
  std::vector<uint8_t> serialize() const;
 private:
  uint64_t size;
  uint64_t attr;
  uint32_t extend;
  char name[36];
  char type[37];
  char guid[37];
  char padding[2];
} __attribute__((__packed__));

struct partition_table_header {
  uint32_t magic;
  uint32_t version = 1;
  uint32_t lun;
  partition_type type;
  uint32_t num;
  char disk_guid[37];
  char padding[3];
} __attribute__((__packed__));

class partition_table {
 public:
  static int current_lun;
  partition_table(const char **attr);
  void add_partition(partition p);
  uint32_t get_lun() const { return header.lun; };
  partition_type get_type() const { return header.type; };
  std::vector<uint8_t> serialize() const;
 private:
  partition_table_header header;
  std::vector<partition> partitions;
};

partition_table **get_partition_table(const std::string fname);
void free_partition_table(partition_table **pt);

class storage_info {
 public:
  storage_info(const std::string);
  const std::vector<partition_table>& get_partition_tables() const
  { return tables; };
  void add_partition_table(partition_table table);
  partition_table& get_last_partition_table() { return tables.back(); };
 private:
  std::vector<partition_table> tables;
};

#endif /* _PARTITION_H_ */
