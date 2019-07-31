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

#include <libvbmeta/libvbmeta.h>
#include <libvbmeta/writer.h>

#include <cmath>

#include <android-base/file.h>

#include <libvbmeta/builder.h>
#include <libvbmeta/reader.h>
#include "utility.h"

namespace android {
namespace fs_mgr {

std::string SerializeSuperVBMeta(const SuperVBMeta& input) {
    std::string vbmeta = "";

    vbmeta.append(reinterpret_cast<const char*>(&input.header), input.header.header_size);

    for (const auto& descriptor : input.descriptors) {
        vbmeta.append(reinterpret_cast<const char*>(&descriptor), SUPER_VBMETA_DESCRIPTOR_SIZE);
        vbmeta.append(descriptor.partition_name, descriptor.partition_name_length);
    }

    // Ensure the size of super_vbmeta.img is a multiple of SUPER_VBMETA_TOTAL_SIZE
    uint32_t resize_to =
            std::ceil(static_cast<double>(vbmeta.size()) / (SUPER_VBMETA_TOTAL_SIZE / 2)) *
            (SUPER_VBMETA_TOTAL_SIZE / 2);
    vbmeta.resize(resize_to, '\0');

    return vbmeta;
}

bool WritePrimaryVBMeta(int fd, const std::string& vbmeta) {
    uint64_t offset = GetPrimaryVBMetaOffset();
    if (lseek(fd, offset, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed";
        return false;
    }

    if (!android::base::WriteFully(fd, vbmeta.data(), vbmeta.size())) {
        PERROR << "Failed to write super primary vbmeta at offset" << offset;
        return false;
    }

    return true;
}

bool WriteBackupVBMeta(int fd, const std::string& vbmeta) {
    uint64_t offset = GetBackupVBMetaOffset(vbmeta.size() * 2);
    if (lseek(fd, offset, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed";
        return false;
    }

    if (!android::base::WriteFully(fd, vbmeta.data(), vbmeta.size())) {
        PERROR << "Failed to write super backup vbmeta at offset" << offset;
        return false;
    }

    return true;
}

}  // namespace fs_mgr
}  // namespace android