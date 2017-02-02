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

#ifndef _SYSTEM_CORE_FASTBOOT_PARTITION_H_
#define _SYSTEM_CORE_FASTBOOT_PARTITION_H_

#include <cstdint>
#include <string>
#include <vector>

enum PartitionType : uint32_t {
  kNone = 0,
  kGpt = 1,
  kUnknown = 0xffffffff,
};

class Partition {
 private:
  struct PartitionHeader {
  uint64_t size;
  uint64_t attr;
  uint32_t extend;
  char name[36];
  char type[37];
  char guid[37];
  char padding[2];
  } __attribute__((__packed__)) header_;
  std::string file_name_;
  std::string pack_;

 public:
  Partition(const char **attr);
  std::vector<uint8_t> Serialize() const;
  static constexpr size_t kSerializeSize = sizeof header_;
};

class PartitionTable {
 public:
  PartitionTable(const char **attr, int lun);
  void AddPartition(Partition p);
  uint32_t GetLun() const { return header_.lun; };
  PartitionType GetType() const { return header_.type; };
  std::vector<uint8_t> Serialize() const;

 private:
  struct PartitionTableHeader {
  uint32_t magic;
  uint32_t version = 1;
  uint32_t lun;
  PartitionType type;
  uint32_t num;
  char disk_guid[37];
  char padding[3];
  } __attribute__((__packed__)) header_;

  std::vector<Partition> partitions_;
};

class StorageInfo {
 public:
  StorageInfo(const std::string);
  const std::vector<PartitionTable> &GetPartitionTables() const {
    return tables_;
  }
  void AddPartitionTable(PartitionTable table_);
  PartitionTable &GetLastPartitionTable() { return tables_.back(); }

 private:
  int depth_;
  int parse_error_;
  std::vector<PartitionTable> tables_;
  int current_lun_;
  static void StartElement(void *data, const char *element, const char **attr);
};

#endif /* _SYSTEM_CORE_FASTBOOT_PARTITION_H_ */
