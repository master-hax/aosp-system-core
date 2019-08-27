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

#include <string_view>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <libavb/libavb.h>
#include <liblp/liblp.h>

#include "builder.h"
#include "reader.h"
#include "utility.h"

using android::base::ErrnoError;
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
        return ErrnoError() << __PRETTY_FUNCTION__ << " lseek failed";
    }

    if (!android::base::WriteFully(fd, table.data(), table.size())) {
        return ErrnoError() << "Failed to write primary vbmeta table at offset " << offset;
    }

    return true;
}

Result<bool> WriteBackupVBMetaTable(int fd, const std::string& table) {
    uint64_t offset = BACKUP_VBMETA_TABLE_OFFSET;
    if (lseek(fd, offset, SEEK_SET) < 0) {
        return ErrnoError() << __PRETTY_FUNCTION__ << " lseek failed";
    }

    if (!android::base::WriteFully(fd, table.data(), table.size())) {
        return ErrnoError() << "Failed to write backup vbmeta table at offset " << offset;
    }

    return true;
}

bool InitVBMetaTablePartition(const IPartitionOpener& opener, const std::string& file) {
    android::base::unique_fd fd = opener.Open(file, O_RDWR | O_SYNC);
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open vbmeta table failed";
        return false;
    }

    VBMetaTableBuilder builder;
    Result<bool> rv = builder.Export(fd);
    if (!rv) {
        LERROR << __PRETTY_FUNCTION__ << " " << rv.error().message();
        return false;
    }

    return true;
}

bool InitVBMetaTablePartition(const std::string& file) {
    return InitVBMetaTablePartition(PartitionOpener(), file);
}

bool UpdateVBMetaTablePartition(const IPartitionOpener& super_opener, const std::string& super_file,
                                const IPartitionOpener& vbmeta_table_opener,
                                const std::string& vbmeta_table_file,
                                const std::string& slot_suffix, const LpMetadata& lpmetadata,
                                const LpMetadataPartition& lppartition,
                                const void* vbmeta_table_buffer) {
    android::base::unique_fd super_fd = super_opener.Open(super_file, O_RDONLY);
    if (super_fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open super failed " << super_file;
        return false;
    }

    android::base::unique_fd vbmeta_table_fd =
            vbmeta_table_opener.Open(vbmeta_table_file, O_RDWR | O_SYNC);
    if (vbmeta_table_fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << " open vbmeta table failed " << vbmeta_table_file;
        return false;
    }

    // Read original vbmeta table
    VBMetaTable vbmeta_table;
    Result<bool> read_vbmeta_table = ReadVBMetaTable(vbmeta_table_fd, 0, &vbmeta_table);
    if (!read_vbmeta_table) {
        LERROR << __PRETTY_FUNCTION__ << " " << read_vbmeta_table.error().message();
        return false;
    }

    VBMetaTableBuilder builder(vbmeta_table);

    // Update vbmeta table
    std::string partition_name(lppartition.name);

    if (vbmeta_table_buffer != nullptr) {
        // Parse avb footer and build physical vbmeta info
        AvbFooter avbfooter;
        if (!ParsePartitionAvbFooter(vbmeta_table_buffer, &avbfooter)) {
            LINFO << __PRETTY_FUNCTION__ << " parse avb footer failed";
            return true;
        }

        Result<std::unique_ptr<VBMetaInfo>> info =
                BuildPhysicalVBMetaInfo(lpmetadata, lppartition, avbfooter);
        if (!info) {
            LERROR << __PRETTY_FUNCTION__ << " " << info.error().message();
            return false;
        }

        // Remove Partition name slot suffix && Check Partition is self-signed
        std::string_view partition_name_without_slot_suffix(partition_name);
        android::base::ConsumeSuffix(&partition_name_without_slot_suffix, slot_suffix);
        Result<bool> partition_is_self_signed = CheckPartitionIsSelfSigned(
                "vbmeta" + slot_suffix, slot_suffix,
                std::string(partition_name_without_slot_suffix.data(),
                            partition_name_without_slot_suffix.length()));
        if (!partition_is_self_signed) {
            LERROR << __PRETTY_FUNCTION__ << " " << partition_is_self_signed.error().message();
            return false;
        }

        // Specify expected AvbVBMetaVerifyResult
        AvbVBMetaVerifyResult expected_result = (partition_is_self_signed.value())
                                                        ? AVB_VBMETA_VERIFY_RESULT_OK
                                                        : AVB_VBMETA_VERIFY_RESULT_OK_NOT_SIGNED;

        // Validate vbmeta
        Result<bool> validate_vbmeta = ValidateVBMetaWithResult(
                super_fd, info.value()->vbmeta_offset, info.value()->vbmeta_size, expected_result);

        if (!validate_vbmeta) {
            LERROR << __PRETTY_FUNCTION__ << " " << validate_vbmeta.error().message();
            return false;
        } else {
            builder.AddVBMetaInfo(**info);
        }
    } else {
        builder.DeleteVBMetaInfo(partition_name);
    }

    Result<bool> export_vbmeta_table = builder.Export(vbmeta_table_fd);
    if (!export_vbmeta_table) {
        LERROR << __PRETTY_FUNCTION__ << " " << export_vbmeta_table.error().message();
        return false;
    }

    return true;
}

bool UpdateVBMetaTablePartition(const std::string& super_file, const std::string& vbmeta_table_file,
                                const std::string& slot_suffix, const LpMetadata& lpmetadata,
                                const LpMetadataPartition& lppartition,
                                const void* vbmeta_table_buffer) {
    return UpdateVBMetaTablePartition(PartitionOpener(), super_file, PartitionOpener(),
                                      vbmeta_table_file, slot_suffix, lpmetadata, lppartition,
                                      vbmeta_table_buffer);
}

}  // namespace fs_mgr
}  // namespace android