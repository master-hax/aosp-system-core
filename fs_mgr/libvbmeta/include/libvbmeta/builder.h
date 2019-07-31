/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <map>
#include <string>

#include <liblp/liblp.h>

#include <libvbmeta/super_vbmeta_format.h>

namespace android {
namespace fs_mgr {

class SuperVBMetaBuilder {
  public:
    SuperVBMetaBuilder();
    SuperVBMetaBuilder(const LpMetadata& metadata,
                       const std::map<std::string, std::string>& images);
    SuperVBMetaBuilder(const SuperVBMeta& footer);
    bool Build();
    bool AddPartitionImage(const LpMetadataPartition& partition, const std::string& file);
    bool Add(const std::string& partition_name, uint64_t vbmeta_offset, uint64_t vbmeta_size);
    bool Delete(const std::string& partition_name);
    std::unique_ptr<SuperVBMeta> Export();
    bool Export(const std::string& file);

  private:
    std::map<std::string, std::pair<uint64_t, uint64_t>> vbmetas_;
    LpMetadata metadata_;
    std::map<std::string, std::string> images_;
};

}  // namespace fs_mgr
}  // namespace android