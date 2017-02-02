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
#include <expat.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

using std::ifstream;
using std::string;
using std::runtime_error;

#define BUF_SIZE 4096
#define FB_PARTITION_MAGIC 0x54504246  //"FBPT" (FastBoot Partition Table)

#define GPT_ATTR_SYSTEM 1
#define GPT_ATTR_BOOTABLE (1ULL << 2)
#define GPT_ATTR_RO (1ULL << 60)
#define GPT_ATTR_HIDDEN (1ULL << 62)

Partition::Partition(const char **attr) {
  // init elements
  header_.size = 0;
  header_.attr = 0;
  header_.extend = 0;
  header_.name[0] = '\0';
  header_.type[0] = '\0';

  for (int i = 0; attr[i]; i += 2) {
    if (!strcmp(attr[i], "label")) {
      strncpy(header_.name, attr[i + 1], sizeof header_.name);
    } else if (!strcmp(attr[i], "type")) {
      strncpy(header_.type, attr[i + 1], sizeof header_.type);
    } else if (!strcmp(attr[i], "guid")) {
      strncpy(header_.guid, attr[i + 1], sizeof header_.guid);
    } else if (!strcmp(attr[i], "size_in_kb")) {
      header_.size = std::strtoul(attr[i + 1], 0, 0) * 1024;
    } else if (!strcmp(attr[i], "bootable") && !strcmp(attr[i + 1], "true")) {
      header_.attr |= GPT_ATTR_BOOTABLE;
    } else if (!strcmp(attr[i], "readonly") && !strcmp(attr[i + 1], "true")) {
      header_.attr |= GPT_ATTR_RO;
    } else if (!strcmp(attr[i], "extend")) {
      header_.extend = !strcmp(attr[i + 1], "true");
    } else if (!strcmp(attr[i], "file")) {
      file_name_ = string(attr[i + 1]);
    } else if (!strcmp(attr[i], "pack")) {
      pack_ = string(attr[i + 1]);
    }
  }

  // validate attributes
  if (header_.name[0] == '\0') throw runtime_error("missing label attr\n");

  if (header_.type[0] == '\0') throw runtime_error("missing type attr\n");
}

std::vector<uint8_t> Partition::Serialize() const {
  std::vector<uint8_t> data(sizeof(header_));

  std::memcpy(&data[0], &header_, sizeof header_);

  return data;
}

void PartitionTable::AddPartition(Partition p) {
  partitions_.push_back(p);
  header_.num++;
}

PartitionTable::PartitionTable(const char **attr, int lun) {
  // init elements
  header_.num = 0;
  header_.magic = FB_PARTITION_MAGIC;
  header_.lun = lun;
  header_.type = kNone;

  for (int i = 0; attr[i]; i += 2) {
    if (!strcmp(attr[i], "lun")) {
      header_.lun = std::strtoul(attr[i + 1], nullptr, 0);
    } else if (!strcmp(attr[i], "type")) {
      if (!strcmp(attr[i + 1], "gpt")) {
        header_.type = kGpt;
      } else {
        header_.type = kUnknown;
        throw runtime_error("partition table type no supported");
      }
    } else if (!strcmp(attr[i], "disk_guid")) {
      strncpy(header_.disk_guid, attr[i + 1], sizeof(header_.disk_guid));
    }
  }
}

void StorageInfo::AddPartitionTable(PartitionTable table) {
  tables_.push_back(table);
}

std::vector<uint8_t> PartitionTable::Serialize() const {
  std::vector<uint8_t> data(partitions_.size() *
                            Partition::kSerializeSize +
                            sizeof(header_), 0);

  std::memcpy(&data[0], &header_, sizeof header_);

  auto pi = &data[0] + sizeof(header_);
  for (auto &p : partitions_) {
    std::memcpy(pi, p.Serialize().data(), Partition::kSerializeSize);
    pi += Partition::kSerializeSize;
  }

  return data;
};

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
    switch ((int)table.GetType()) {
      case kNone:
      // if type was not specified default to GPT
      case kGpt:
        table.AddPartition(Partition(attr));
        break;
      default:
        fprintf(stderr, "partition type not supported\n");
        self->parse_error_ = true;
    }
  }
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
