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

#include <android-base/logging.h>
#include <expat.h>
#include <cstring>
#include <fstream>
#include "storage_info.h"

using std::string;

// helper class for xml parsing
class Parser {
  public:
    int ParseXml(StorageInfo* info, string fname);

  private:
    int depth_;
    int parse_error_;
    int next_lun_;
    bool storage_flag_;
    StorageInfo* stor_info_;
    static void StartElement(void* data, const char* element, const char** attr);
    static int ParsePartitionTable(const char**, PartitionTable&, int);
    static int ParsePartition(const char**, Partition&);
};

int Parser::ParsePartition(const char** attr, Partition& part) {
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
        } else if (!strcmp(attr[i], "erase-block-align") && !strcmp(attr[i + 1], "true")) {
            part.erase_block_align = true;
        } else if (!strcmp(attr[i], "filename")) {
            part.file_name = string(attr[i + 1]);
        } else if (!strcmp(attr[i], "group")) {
            part.group = string(attr[i + 1]);
        }
    }

    // validate attributes
    if (part.name.empty()) return LOG(ERROR) << "missing label attr\n", -1;

    if (part.type.empty()) return LOG(ERROR) << "missing type attr\n", -1;

    return 0;
}

int Parser::ParsePartitionTable(const char** attr, PartitionTable& table, int lun) {
    // assigned next lun by default
    table.lun = lun;

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
                LOG(ERROR) << "partition table type " << attr[i + 1] << " no suported\n";
                return -1;
            }
        } else if (!strcmp(attr[i], "disk_guid")) {
            table.disk_guid = attr[i + 1];
        }
    }

    return 0;
}

void Parser::StartElement(void* data, const char* element, const char** attr) {
    Parser* self = static_cast<Parser*>(data);

    self->depth_++;

    // if there is already an error no point continuing
    if (self->parse_error_) return;

    if (!strcmp(element, "storage")) {
        if (self->depth_ != 1 || self->storage_flag_) {
            self->parse_error_ = true;
            return;
        }

        // parse attributes storage attributes
        StorageInfo* info = self->stor_info_;
        for (int i = 0; attr[i]; i += 2) {
            if (!strcmp(attr[i], "type")) {
                if (!strcmp(attr[i + 1], "ufs")) {
                    info->SetType(StorageType::kUfs);
                } else if (!strcmp(attr[i + 1], "ufs")) {
                    info->SetType(StorageType::kEmmc);
                } else {
                    self->parse_error_ = true;
                    LOG(ERROR) << "Storage type no supported\n";
                }
            }
        }
        self->storage_flag_ = true;
    } else if (!strcmp(element, "volume")) {
        if (self->depth_ != 2) {
            self->parse_error_ = true;
            return;
        }

        PartitionTable table{};
        if (ParsePartitionTable(attr, table, self->next_lun_)) {
            self->parse_error_ = true;
        } else {
            // set next lun
            self->next_lun_ = table.lun + 1;
            self->stor_info_->AddPartitionTable(table);
        }
    } else if (!strcmp(element, "partition")) {
        if (self->depth_ != 3) {
            self->parse_error_ = true;
            return;
        }
        auto part = Partition();
        if (ParsePartition(attr, part))
            self->parse_error_ = true;
        else
            self->stor_info_->AddPartition(part);
    }
}

int Parser::ParseXml(StorageInfo* info, string fname) {
    stor_info_ = info;

    std::ifstream f(fname);
    if (!f.is_open()) {
        LOG(ERROR) << "cannot open file " << fname << '\n';
        return -1;
    }

    // end_element function only decrease depth, so make it an anonymous func
    auto end_function = [](void* data, const char*) {
        Parser* self = static_cast<Parser*>(data);
        self->depth_--;
    };

    XML_Parser parser = XML_ParserCreate(nullptr);
    XML_SetElementHandler(parser, &Parser::StartElement, end_function);
    XML_SetUserData(parser, this);

    static constexpr int kBufLen = 4096;

    while (!parse_error_) {
        char* buf = static_cast<char*>(XML_GetBuffer(parser, kBufLen));
        f.read((char*)buf, kBufLen);
        XML_ParseBuffer(parser, f.gcount(), f.eof());
        if (f.eof()) break;
    }

    XML_ParserFree(parser);
    f.close();

    if (parse_error_) return LOG(ERROR) << "error parsing file\n", -1;

    return 0;
}

void StorageInfo::AddPartitionTable(const PartitionTable& table) {
    tables_.push_back(table);
    if (!table.group.empty()) groups_.insert(table.group);
}

void StorageInfo::AddPartition(const Partition& part) {
    // always add partition to the last partition table
    tables_.back().partitions.push_back(part);
    if (!part.group.empty()) groups_.insert(part.group);
}

std::vector<Partition> StorageInfo::GetPartitionsByGroup(std::string name) const {
    auto v = std::vector<Partition>();

    for (auto& pt : tables_)
        for (auto& p : pt.partitions)
            if (name == p.group) v.push_back(p);

    return v;
}

std::vector<PartitionTable> StorageInfo::GetPartitionTablesByGroup(std::string name) const {
    auto v = std::vector<PartitionTable>();

    for (auto& pt : tables_)
        if (name == pt.group) v.push_back(pt);

    return v;
}

std::unique_ptr<StorageInfo> StorageInfo::NewStorageInfo(const std::string& fname) {
    auto info = std::unique_ptr<StorageInfo>(new StorageInfo());
    if (Parser().ParseXml(info.get(), fname)) return nullptr;
    return info;
}
