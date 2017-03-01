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

#include <expat.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include "storage_info.h"

using std::string;

int StorageInfo::ParseAndAddPartition(StorageInfo *self, const char **attr) {
  Partition part = Partition();

  for (int i = 0; attr[i]; i += 2) {
    if (!strcmp(attr[i], "label")) {
      part.name = attr[i + 1];
    } else if (!strcmp(attr[i], "type")) {
      part.type = attr[i + 1];
    } else if (!strcmp(attr[i], "guid")) {
      part.guid = attr[i + 1];
    } else if (!strcmp(attr[i], "size_in_kb")) {
      part.size = std::strtoul(attr[i + 1], 0, 0) * 1024;
    } else if (!strcmp(attr[i], "bootable") && !strcmp(attr[i + 1], "true")) {
      part.bootable = true;
    } else if (!strcmp(attr[i], "readonly") && !strcmp(attr[i + 1], "true")) {
      part.readonly = true;
    } else if (!strcmp(attr[i], "extend") && !strcmp(attr[i + 1], "true")) {
      part.extend = true;
    } else if (!strcmp(attr[i], "erase-block-align") &&
               !strcmp(attr[i + 1], "true")) {
      part.erase_block_align = true;
    } else if (!strcmp(attr[i], "filename")) {
      part.file_name = string(attr[i + 1]);
    } else if (!strcmp(attr[i], "group")) {
      part.group = string(attr[i + 1]);
    }
  }

  // validate attributes
  if (part.name.empty()) return fprintf(stderr, "missing label attr\n"), -1;

  if (part.type.empty()) return fprintf(stderr, "missing type attr\n"), -1;

  self->AddPartition(part);

  return 0;
}

std::vector<Partition> StorageInfo::GetPartitionsByGroup(
    std::string name) const {
  auto v = std::vector<Partition>();

  for (auto &pt : tables_)
    for (auto &p : pt.partitions)
      if (name == p.group) v.push_back(p);

  return v;
}

int StorageInfo::ParseAndAddPartitionTable(StorageInfo *self,
                                           const char **attr) {
  PartitionTable table{};

  // assigned next lun by default
  table.lun = self->next_lun_;

  for (int i = 0; attr[i]; i += 2) {
    if (!strcmp(attr[i], "lun")) {
      table.lun = std::strtoul(attr[i + 1], nullptr, 0);
    } else if (!strcmp(attr[i], "group")) {
      table.group = attr[i + 1];
    } else if (!strcmp(attr[i], "type")) {
      if (!strcmp(attr[i + 1], "gpt")) {
        table.type = PartitionType::kGpt;
      } else if (!strcmp(attr[i + 1], "msdos")) {
        table.type = PartitionType::kMsdos;
      } else {
        fprintf(stderr, "partition table type %s no supported", attr[i + 1]);
        return -1;
      }
    } else if (!strcmp(attr[i], "disk_guid")) {
      table.disk_guid = attr[i + 1];
    }
  }
  // set next lun
  self->next_lun_ = table.lun + 1;

  self->AddPartitionTable(table);

  return 0;
}

void StorageInfo::AddPartitionTable(const PartitionTable &table) {
  tables_.push_back(table);
  if (!table.group.empty()) groups_.insert(table.group);
}

void StorageInfo::AddPartition(const Partition &part) {
  // always add partition to the last partition table
  tables_.back().partitions.push_back(part);
  if (!part.group.empty()) groups_.insert(part.group);
}

void StorageInfo::StartElement(void *data, const char *element,
                               const char **attr) {
  static int storage;
  StorageInfo *self = static_cast<StorageInfo *>(data);

  self->depth_++;

  // if there is already an error no point continuing
  if (self->parse_error_) return;

  if (!strcmp(element, "storage")) {
    if (self->depth_ != 1 || storage) {
      self->parse_error_ = true;
      return;
    }

    // parse attributes
    for (int i = 0; attr[i]; i += 2) {
      if (!strcmp(attr[i], "type")) {
        if (!strcmp(attr[i + 1], "ufs")) {
          self->type_ = StorageType::kUfs;
        } else if (!strcmp(attr[i + 1], "ufs")) {
          self->type_ = StorageType::kEmmc;
        } else {
          self->parse_error_ = true;
          fprintf(stderr, "Storage type no supported");
        }
      }
    }
    storage = true;
  } else if (!strcmp(element, "volume")) {
    if (self->depth_ != 2) {
      self->parse_error_ = true;
      return;
    }
    if (ParseAndAddPartitionTable(self, attr)) self->parse_error_ = true;
  } else if (!strcmp(element, "partition")) {
    if (self->depth_ != 3) {
      self->parse_error_ = true;
      return;
    }
    if (ParseAndAddPartition(self, attr)) self->parse_error_ = true;
  }
}

std::vector<PartitionTable> StorageInfo::GetPartitionTablesByGroup(
    std::string name) const {
  auto v = std::vector<PartitionTable>();

  for (auto &pt : tables_)
    if (name == pt.group) v.push_back(pt);

  return v;
}

std::unique_ptr<StorageInfo> StorageInfo::NewStorageInfo(
    const std::string &fname) {
  auto info = std::unique_ptr<StorageInfo>(new StorageInfo());

  std::ifstream f(fname);
  if (!f.is_open()) {
    fprintf(stderr, "cannot open file %s\n", fname.c_str());
    return nullptr;
  }

  // end_element function only decrease depth, so make it an anonymous func
  auto end_function = [](void *data, const char *) {
    StorageInfo *self = static_cast<StorageInfo *>(data);
    self->depth_--;
  };

  XML_Parser parser = XML_ParserCreate(nullptr);
  XML_SetElementHandler(parser, &StorageInfo::StartElement, end_function);
  XML_SetUserData(parser, info.get());

  static constexpr int kBufLen = 4096;

  while (!info->parse_error_) {
    char *buf = static_cast<char *>(XML_GetBuffer(parser, kBufLen));
    f.read((char *)buf, kBufLen);
    XML_ParseBuffer(parser, f.gcount(), f.eof());
    if (f.eof()) break;
  }

  XML_ParserFree(parser);
  f.close();

  if (info->parse_error_) {
    fprintf(stderr, "error parsing file\n");
    return nullptr;
  }
  return info;
}
