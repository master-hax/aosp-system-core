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
//#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "storage_info.h"

using std::ifstream;
using std::string;
using std::runtime_error;

#define BUF_SIZE 4096

Partition::Partition(const char **attr)
    : size_(0), bootable_(false), readonly_(false), extend_(false) {
  for (int i = 0; attr[i]; i += 2) {
    if (!strcmp(attr[i], "label")) {
      name_ = attr[i + 1];
    } else if (!strcmp(attr[i], "type")) {
      type_ = attr[i + 1];
    } else if (!strcmp(attr[i], "guid")) {
      guid_ = attr[i + 1];
    } else if (!strcmp(attr[i], "size_in_kb")) {
      size_ = std::strtoul(attr[i + 1], 0, 0) * 1024;
    } else if (!strcmp(attr[i], "bootable") && !strcmp(attr[i + 1], "true")) {
      bootable_ = true;
    } else if (!strcmp(attr[i], "readonly") && !strcmp(attr[i + 1], "true")) {
      readonly_ = true;
    } else if (!strcmp(attr[i], "extend")) {
      extend_ = true;
    } else if (!strcmp(attr[i], "filename")) {
      file_name_ = string(attr[i + 1]);
    } else if (!strcmp(attr[i], "group")) {
      group_ = string(attr[i + 1]);
    }
  }

  // validate attributes
  if (name_.empty()) throw runtime_error("missing label attr\n");

  if (type_.empty()) throw runtime_error("missing type attr\n");
}

const Partition *PartitionTable::FindPartitionByName(std::string name) const {
  for (auto &p : partitions_)
    if (name == p.GetName()) return &p;

  return nullptr;
}

std::vector<Partition> PartitionTable::GetPartitionsByGroup(
    std::string name) const {
  auto v = std::vector<Partition>();

  for (auto &p : partitions_)
    if (name == p.GetGroupName()) v.push_back(p);

  return v;
}

void PartitionTable::AddPartition(Partition p) { partitions_.push_back(p); }

PartitionTable::PartitionTable(const char **attr, int lun) : lun_(lun) {
  for (int i = 0; attr[i]; i += 2) {
    if (!strcmp(attr[i], "lun")) {
      lun_ = std::strtoul(attr[i + 1], nullptr, 0);
    } else if (!strcmp(attr[i], "group")) {
      group_ = attr[i + 1];
    } else if (!strcmp(attr[i], "type")) {
      if (!strcmp(attr[i + 1], "gpt")) {
        type_ = PartitionType::kGpt;
      } else {
        type_ = PartitionType::kUnknown;
        throw runtime_error("partition table type no supported");
      }
    } else if (!strcmp(attr[i], "disk_guid")) {
      disk_guid_ = attr[i + 1];
    }
  }
}

void StorageInfo::AddPartitionTable(PartitionTable table) {
  tables_.push_back(table);
  if (!table.GetGroupName().empty()) groups_.insert(table.GetGroupName());
}

void StorageInfo::AddPartition(PartitionTable table, Partition partition) {
  table.AddPartition(partition);
  if (!partition.GetGroupName().empty())
    groups_.insert(partition.GetGroupName());
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
          throw runtime_error("Storage type no supported");
        }
      }
    }
    storage = true;
  } else if (!strcmp(element, "volume")) {
    if (self->depth_ != 2) {
      self->parse_error_ = true;
      return;
    }
    PartitionTable partition_table(attr, self->current_lun_);
    self->current_lun_ = partition_table.GetLun() + 1;
    self->AddPartitionTable(partition_table);
  } else if (!strcmp(element, "partition")) {
    if (self->depth_ != 3) {
      self->parse_error_ = true;
      return;
    }
    PartitionTable &table = self->GetLastPartitionTable();
    switch (table.GetType()) {
      case PartitionType::kNone:
      // if type was not specified default to GPT
      case PartitionType::kGpt:
        // self->AddPartition(table, Partition(attr));
        table.AddPartition(Partition(attr));
        break;
      default:
        fprintf(stderr, "partition type not supported\n");
        self->parse_error_ = true;
    }
  }
}

std::vector<PartitionTable> StorageInfo::GetPartitionTablesByGroup(
    std::string name) const {
  auto v = std::vector<PartitionTable>();

  for (auto &pt : tables_)
    if (name == pt.GetGroupName()) v.push_back(pt);

  return v;
}

StorageInfo::StorageInfo(const std::string fname) {
  XML_Parser parser = XML_ParserCreate(nullptr);
  ifstream f(fname);
  depth_ = 0;
  parse_error_ = 0;
  current_lun_ = 0;

  if (!f.is_open())
    throw std::runtime_error(string("cannot open file ") + fname + '\n');

  // end_element function only decrease depth, so make it an anonymous func
  auto end_function = [](void *data, const char *) {
    StorageInfo *self = static_cast<StorageInfo *>(data);
    self->depth_--;
  };

  XML_SetElementHandler(parser, &StorageInfo::StartElement, end_function);
  XML_SetUserData(parser, this);

  while (!parse_error_) {
    char *buf = static_cast<char *>(XML_GetBuffer(parser, BUF_SIZE));
    f.read((char *)buf, BUF_SIZE);
    XML_ParseBuffer(parser, f.gcount(), f.eof());
    if (f.eof()) break;
  }

  XML_ParserFree(parser);
  f.close();

  if (parse_error_) throw runtime_error("error parsing file\n");
}
