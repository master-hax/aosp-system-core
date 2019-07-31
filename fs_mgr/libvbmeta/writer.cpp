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

#include "writer.h"

#include <android-base/file.h>

using android::base::Error;
using android::base::Result;

namespace android {
namespace fs_mgr {

std::string SerializeVBMetaTable(const VBMetaTable& input) {
    std::string table;
    table.append(reinterpret_cast<const char*>(&input.header), VBMETA_TABLE_HEADER_SIZE);

    for (const auto& descriptor : input.descriptors) {
        table.append(reinterpret_cast<const char*>(&descriptor), VBMETA_TABLE_DESCRIPTOR_SIZE);
        table.append(descriptor.partition_name);
    }

    // Ensure the size of vbmeta table is VBMETA_TABLE_MAX_SIZE
    table.resize(VBMETA_TABLE_MAX_SIZE, '\0');

    return table;
}

Result<bool> WritePrimaryVBMetaTable(int fd, const std::string& table) {
    uint64_t offset = PRIMARY_VBMETA_TABLE_OFFSET;
    if (lseek(fd, offset, SEEK_SET) < 0) {
        return Error() << __PRETTY_FUNCTION__ << " lseek failed";
    }

    if (!android::base::WriteFully(fd, table.data(), table.size())) {
        return Error() << "Failed to write primary vbmeta table at offset " << offset;
    }

    return true;
}

Result<bool> WriteBackupVBMetaTable(int fd, const std::string& table) {
    uint64_t offset = BACKUP_VBMETA_TABLE_OFFSET;
    if (lseek(fd, offset, SEEK_SET) < 0) {
        return Error() << __PRETTY_FUNCTION__ << " lseek failed";
    }

    if (!android::base::WriteFully(fd, table.data(), table.size())) {
        return Error() << "Failed to write backup vbmeta table at offset " << offset;
    }

    return true;
}

}  // namespace fs_mgr
}  // namespace android