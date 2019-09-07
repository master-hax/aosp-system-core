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

#include <android-base/result.h>

#include "super_vbmeta_format.h"

namespace android {
namespace fs_mgr {

class SuperVBMetaBuilder {
  public:
    SuperVBMetaBuilder();
    SuperVBMetaBuilder(const int super_vbmeta_fd,
                       const std::map<std::string, std::string>& images_path);
    SuperVBMetaBuilder(const int super_vbmeta_fd);
    SuperVBMetaBuilder(const int super_vbmeta_fd, const VBMetaTable& table);
    android::base::Result<void> Build();
    android::base::Result<std::string> ReadVBMetaImageFromFile(const std::string& file);
    android::base::Result<uint8_t> /* slot number */ AddVBMetaImage(const std::string& vbmeta_name);
    void DeleteVBMetaImage(const std::string& vbmeta_name);
    std::unique_ptr<VBMetaTable> ExportVBMetaTable();
    android::base::Result<void> ExportVBMetaTableToFile();
    android::base::Result<void> ExportVBMetaImageToFile(const uint8_t vbmeta_slot,
                                                        const std::string& vbmeta_image);

  private:
    android::base::Result<uint8_t> GetEmptySlot();

    int super_vbmeta_fd_;
    VBMetaTable table_;
    std::map<std::string /* vbmeta image name */, std::string /* vbmeta image file path */>
            images_path_;
};

}  // namespace fs_mgr
}  // namespace android