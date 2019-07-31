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

#include <string>

#include <android-base/result.h>
#include <liblp/liblp.h>

#include "vbmeta_table_format.h"

namespace android {
namespace fs_mgr {

class VBMetaTableBuilder {
  public:
    VBMetaTableBuilder();
    VBMetaTableBuilder(const std::string& super_file, const LpMetadata& lpmetadata,
                       const std::map<std::string, std::string>& images_path);
    VBMetaTableBuilder(const VBMetaTable& table);
    android::base::Result<bool> Build();
    android::base::Result<bool> AddVBMetaInfoForPartition(
            const LpMetadataPartition& partition,
            const std::string& file /* partition file name */);
    void AddVBMetaInfo(const VBMetaInfo& input);
    void DeleteVBMetaInfo(const std::string& partition_name);
    std::unique_ptr<VBMetaTable> Export();
    android::base::Result<bool> Export(const std::string& file);
    android::base::Result<bool> Export(int fd);

  private:
    std::string super_file_;
    std::vector<VBMetaInfo> vbmeta_info_;
    LpMetadata lpmetadata_;
    std::map<std::string /* partition name */, std::string /* image file path */> images_path_;
};

}  // namespace fs_mgr
}  // namespace android