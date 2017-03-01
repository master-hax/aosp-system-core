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

enum class PartitionType : uint32_t {
  kNone = 0,
  kGpt = 1,
  kUnknown = 0xffffffff,
};

class Partition {
 public:
  Partition() = default;
  Partition(const char **attr);
  std::string GetName() const { return name_; };
  std::string GetType() const { return type_; };
  std::string GetGuid() const { return guid_; };
  std::string GetFileName() const { return file_name_; };
  std::string GetGroupName() const { return group_; };
  size_t GetSize() const { return size_; };
  bool IsBootable() const { return bootable_; };
  bool IsReadOnly() const { return readonly_; };
  bool IsExtended() const { return extend_; };
  bool IsEraseBlockSizeAligned() const { return erase_block_align_; };

 private:
  std::string name_;
  std::string type_;
  std::string guid_;
  std::string file_name_;
  std::string group_;
  uint64_t size_;
  bool bootable_;
  bool readonly_;
  bool extend_;
  bool erase_block_align_;
};

class PartitionTable {
 public:
  PartitionTable(const char **attr, int lun);
  void AddPartition(Partition p);
  uint32_t GetLun() const { return lun_; };
  PartitionType GetType() const { return type_; };
  uint32_t GetNumOfPartitions() const { return partitions_.size(); };
  std::string GetDiskGuid() const { return disk_guid_; };
  std::string GetGroupName() const { return group_; };
  const Partition *FindPartitionByName(std::string name) const;
  std::vector<Partition> GetPartitionsByGroup(std::string name) const;
  const std::vector<Partition> &GetPartitions() const { return partitions_; }

 private:
  uint32_t lun_;
  PartitionType type_{PartitionType::kGpt};
  std::string disk_guid_;
  std::string group_;
  std::vector<Partition> partitions_;
};

enum class StorageType : uint32_t {
  kUfs = 0,
  kEmmc = 1,
};

class StorageInfo {
 public:
  StorageInfo(const std::string);
  const std::vector<PartitionTable> &GetPartitionTables() const {
    return tables_;
  }
  std::vector<PartitionTable> GetPartitionTablesByGroup(std::string name) const;
  void AddPartitionTable(PartitionTable table);
  void AddPartition(PartitionTable table, Partition partition);
  PartitionTable &GetLastPartitionTable() { return tables_.back(); }
  std::set<std::string> GetGroups() const { return groups_; }

 private:
  StorageType type_{StorageType::kUfs};
  int depth_;
  int parse_error_;
  std::vector<PartitionTable> tables_;
  int current_lun_;
  std::set<std::string> groups_;
  static void StartElement(void *data, const char *element, const char **attr);
};

#endif /* _SYSTEM_CORE_LIBSTORAGEINFO_INCLUDE_H_ */
