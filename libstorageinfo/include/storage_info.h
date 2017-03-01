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

#ifndef _SYSTEM_CORE_LIBSTORAGEINFO_INCLUDE_H_
#define _SYSTEM_CORE_LIBSTORAGEINFO_INCLUDE_H_

#include <cstdint>
#include <set>
#include <string>
#include <vector>
#include <memory>

enum class PartitionType : uint32_t {
  kGpt = 0,
  kMsdos = 1,
};

struct Partition {
  std::string name;
  std::string type;
  std::string guid;
  std::string file_name;
  std::string group;
  uint64_t size;
  bool bootable;
  bool readonly;
  bool extend;
  bool erase_block_align;
};

struct PartitionTable {
  uint32_t lun;
  PartitionType type{PartitionType::kGpt};
  std::string disk_guid;
  std::string group;
  std::vector<Partition> partitions;
};

enum class StorageType : uint32_t {
  kUfs = 0,
  kEmmc = 1,
};

class StorageInfo {
 public:
  // Factory Method
  static std::unique_ptr<StorageInfo> NewStorageInfo(const std::string&);
  // StorageInfo is not copyable
  StorageInfo(const StorageInfo&) = delete;
  StorageInfo& operator=(const StorageInfo&) = delete;
  const std::vector<PartitionTable> &GetPartitionTables() const {
    return tables_;
  }
  std::vector<PartitionTable> GetPartitionTablesByGroup(std::string name) const;
  std::vector<Partition> GetPartitionsByGroup(std::string name) const;
  std::set<std::string> GetGroups() const { return groups_; }
  StorageType GetType() const { return type_; }

 private:
  StorageInfo() = default;
  StorageType type_{StorageType::kUfs};
  int depth_;
  int parse_error_;
  std::vector<PartitionTable> tables_;
  int next_lun_;
  std::set<std::string> groups_;
  void AddPartitionTable(const PartitionTable& table);
  void AddPartition(const Partition& partition);
  static void StartElement(void *data, const char *element, const char **attr);
  static int ParseAndAddPartitionTable(StorageInfo *, const char **);
  static int ParseAndAddPartition(StorageInfo *, const char **);
};

#endif /* _SYSTEM_CORE_LIBSTORAGEINFO_INCLUDE_H_ */
