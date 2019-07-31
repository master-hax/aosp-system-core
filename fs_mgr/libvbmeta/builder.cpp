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

#include "builder.h"

#include <algorithm>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <openssl/sha.h>
#include <sparse/sparse.h>

#include "utility.h"
#include "writer.h"

using android::base::Error;
using android::base::Result;
using SparsePtr = std::unique_ptr<sparse_file, decltype(&sparse_file_destroy)>;

namespace android {
namespace fs_mgr {

VBMetaTableBuilder::VBMetaTableBuilder() {}

VBMetaTableBuilder::VBMetaTableBuilder(const std::string& super_file, const LpMetadata& lpmetadata,
                                       const std::map<std::string, std::string>& images_path)
    : super_file_(super_file), lpmetadata_(lpmetadata), images_path_(images_path) {}

VBMetaTableBuilder::VBMetaTableBuilder(const VBMetaTable& table) {
    for (const auto& descriptor : table.descriptors) {
        AddVBMetaInfo(VBMetaInfo{descriptor.vbmeta_offset, descriptor.vbmeta_size,
                                 descriptor.partition_name});
    }
}

Result<bool> VBMetaTableBuilder::Build() {
    for (const auto& partition : lpmetadata_.partitions) {
        auto iter = images_path_.find(std::string(partition.name));
        if (iter == images_path_.end()) {
            continue;
        }
        Result<bool> rv = AddVBMetaInfoForPartition(partition, iter->second /* file name */);
        if (!rv) {
            return rv.error();
        }
        images_path_.erase(iter);
    }
    return true;
}

Result<bool> VBMetaTableBuilder::AddVBMetaInfoForPartition(const LpMetadataPartition& partition,
                                                           const std::string& file) {
    android::base::unique_fd source_fd(
            TEMP_FAILURE_RETRY(open(file.c_str(), O_RDONLY | O_CLOEXEC)));
    if (source_fd < 0) {
        return Error() << "Couldn't open partition image file " << file;
    }

    int fd = source_fd.get();

    SparsePtr source(sparse_file_import(source_fd, true /* verbose */, true /* crc */),
                     sparse_file_destroy);
    TemporaryFile unsparsed_file;
    if (unsparsed_file.fd < 0) {
        return Error() << "Couldn't make temporary file";
    }

    // Converts to a raw file if the input is in sparse format.
    if (source) {
        int rv = sparse_file_write(source.get(), unsparsed_file.fd, false /* gz */,
                                   false /* sparse */, false /* crc */);
        if (rv) {
            return Error() << "sparse_file_write failed with code " << rv;
        }
        fd = unsparsed_file.fd;
    }

    // Load avb footer and build physical vbmeta info
    const uint64_t partition_size = ComputePartitionSize(lpmetadata_, partition);
    Result<std::unique_ptr<AvbFooter>> avbfooter = LoadAvbFooter(fd, partition_size);
    if (!avbfooter) {
        return avbfooter.error();
    }

    Result<std::unique_ptr<VBMetaInfo>> info =
            BuildPhysicalVBMetaInfo(lpmetadata_, partition, **avbfooter);
    if (!info) {
        return info.error();
    }

    // Open super image file and validate vbmeta
    android::base::unique_fd super_fd(
            TEMP_FAILURE_RETRY(open(super_file_.c_str(), O_RDONLY | O_CLOEXEC)));
    if (super_fd < 0) {
        return Error() << "Couldn't open super image file " << super_file_;
    }

    Result<bool> validate_vbmeta =
            ValidateVBMeta(super_fd, info.value()->vbmeta_offset, info.value()->vbmeta_size);
    if (!validate_vbmeta) {
        return validate_vbmeta.error();
    }

    // Add vbmeta info
    AddVBMetaInfo(**info);

    return true;
}

void VBMetaTableBuilder::AddVBMetaInfo(const VBMetaInfo& input) {
    auto info = std::find_if(vbmeta_info_.begin(), vbmeta_info_.end(), [&input](const auto& entry) {
        return entry.partition_name == input.partition_name;
    });
    if (info != vbmeta_info_.end()) {
        info->vbmeta_offset = input.vbmeta_offset;
        info->vbmeta_size = input.vbmeta_size;
    } else {
        vbmeta_info_.emplace_back(input);
    }
}

void VBMetaTableBuilder::DeleteVBMetaInfo(const std::string& partition_name) {
    auto info = std::find_if(
            vbmeta_info_.begin(), vbmeta_info_.end(),
            [partition_name](const auto& entry) { return entry.partition_name == partition_name; });
    if (info != vbmeta_info_.end()) {
        vbmeta_info_.erase(info);
    }
}

std::unique_ptr<VBMetaTable> VBMetaTableBuilder::Export() {
    std::unique_ptr<VBMetaTable> table = std::make_unique<VBMetaTable>();

    uint32_t descriptors_size = 0;

    // export descriptors
    for (const auto& info : vbmeta_info_) {
        InternalVBMetaDescriptor descriptor;
        descriptor.vbmeta_offset = info.vbmeta_offset;
        descriptor.vbmeta_size = info.vbmeta_size;
        descriptor.partition_name_length = info.partition_name.length();
        descriptor.partition_name = info.partition_name;
        memset(descriptor.reserved, 0, sizeof(descriptor.reserved));
        table->descriptors.emplace_back(std::move(descriptor));

        descriptors_size +=
                VBMETA_TABLE_DESCRIPTOR_SIZE + descriptor.partition_name_length * sizeof(char);
    }

    // export header
    table->header.magic = VBMETA_TABLE_MAGIC;
    table->header.major_version = VBMETA_TABLE_MAJOR_VERSION;
    table->header.minor_version = VBMETA_TABLE_MINOR_VERSION;
    table->header.header_size = VBMETA_TABLE_HEADER_SIZE;
    table->header.total_size = VBMETA_TABLE_HEADER_SIZE + descriptors_size;
    memset(table->header.checksum, 0, sizeof(table->header.checksum));
    table->header.descriptors_size = descriptors_size;
    memset(table->header.reserved, 0, sizeof(table->header.reserved));
    std::string serial = SerializeVBMetaTable(*table);
    ::SHA256(reinterpret_cast<const uint8_t*>(serial.c_str()), table->header.total_size,
             table->header.checksum);
    return table;
}

Result<bool> VBMetaTableBuilder::Export(int fd) {
    std::unique_ptr<VBMetaTable> table = Export();

    std::string serialized_table = SerializeVBMetaTable(*table);

    android::base::Result<bool> write_primary_vbmeta_table =
            WritePrimaryVBMetaTable(fd, serialized_table);
    if (!write_primary_vbmeta_table) {
        return write_primary_vbmeta_table.error();
    }

    android::base::Result<bool> write_backup_vbmeta_table =
            WriteBackupVBMetaTable(fd, serialized_table);
    if (!write_backup_vbmeta_table) {
        return write_backup_vbmeta_table.error();
    }

    return true;
}

Result<bool> VBMetaTableBuilder::Export(const std::string& file) {
    android::base::unique_fd fd(
            TEMP_FAILURE_RETRY(open(file.c_str(), O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644)));
    if (fd.get() < 0) {
        return Error() << "Couldn't export vbmeta table in " << file;
    }

    return Export(fd.get());
}

bool WriteToVBMetaTableFile(const std::string& super_file, const std::string& vbmeta_table_file,
                            const LpMetadata& lpmetadata,
                            const std::map<std::string, std::string>& images) {
    VBMetaTableBuilder builder(super_file, lpmetadata, images);
    return builder.Build() && builder.Export(vbmeta_table_file);
}

}  // namespace fs_mgr
}  // namespace android