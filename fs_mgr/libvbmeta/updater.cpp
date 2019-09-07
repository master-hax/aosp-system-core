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

#include "libvbmeta/libvbmeta.h"

#include <liblp/partition_opener.h>

#include "builder.h"
#include "reader.h"
#include "utility.h"
#include "writer.h"

using android::base::Result;
using android::base::unique_fd;

namespace android {
namespace fs_mgr {

bool InitSuperVBMetaPartition(const std::string& super_vbmeta_name) {
    unique_fd fd = PartitionOpener().Open(super_vbmeta_name, O_RDWR | O_SYNC);
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open super vbmeta failed";
        return false;
    }

    SuperVBMetaBuilder builder(fd);
    Result<void> rv = builder.ExportVBMetaTableToFile();
    if (!rv) {
        LERROR << __PRETTY_FUNCTION__ << " " << rv.error();
        return false;
    }

    return true;
}

bool UpdateSuperVBMetaPartition(const std::string& super_vbmeta_name,
                                const std::string& vbmeta_image_name,
                                const std::optional<std::string> vbmeta_image) {
    unique_fd fd = PartitionOpener().Open(super_vbmeta_name, O_RDWR | O_SYNC);
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open super vbmeta failed";
        return false;
    }

    // Read original vbmeta table
    VBMetaTable table;
    Result<void> read_primary_vbmeta_table = ReadPrimaryVBMetaTable(fd, &table);
    if (!read_primary_vbmeta_table) {
        LERROR << __PRETTY_FUNCTION__ << " " << read_primary_vbmeta_table.error();
        return false;
    }

    SuperVBMetaBuilder builder(fd, table);

    // Update super vbmeta
    if (vbmeta_image) {
        Result<uint8_t> vbmeta_index = builder.AddVBMetaImage(vbmeta_image_name);
        if (!vbmeta_index) {
            LERROR << __PRETTY_FUNCTION__ << " " << vbmeta_index.error();
            return false;
        }
        builder.ExportVBMetaImageToFile(vbmeta_index.value(), *vbmeta_image);
    } else {
        // There is in_use in SuperVBMetaHeader to mark which slot is in use
        // so cleaning the vbmeta image in super vbmeta isn't needed.
        builder.DeleteVBMetaImage(vbmeta_image_name);
    }

    // Export vbmeta table to super vbmeta
    Result<void> export_vbmeta_table = builder.ExportVBMetaTableToFile();
    if (!export_vbmeta_table) {
        LERROR << __PRETTY_FUNCTION__ << " " << export_vbmeta_table.error();
        return false;
    }

    return true;
}

}  // namespace fs_mgr
}  // namespace android