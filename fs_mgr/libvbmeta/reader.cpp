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

#include "reader.h"

#include <android-base/file.h>

using android::base::Error;
using android::base::Result;

namespace android {
namespace fs_mgr {

Result<bool> LoadAndVerifyVBMetaTableHeader(const void* buffer, VBMetaTableHeader* header) {
    memcpy(header, buffer, sizeof(*header));

    // Do basic validation of vbmeta table.
    if (header->magic != VBMETA_TABLE_MAGIC) {
        return Error() << "VBMeta Table has invalid magic value";
    }

    // Check that the version is compatible.
    if (header->major_version != VBMETA_TABLE_MAJOR_VERSION ||
        header->minor_version > VBMETA_TABLE_MINOR_VERSION) {
        return Error() << "VBMeta Table has incompatible version";
    }

    return true;
}

Result<bool> LoadAndVerifyVBMetaDescriptors(const void* buffer, uint32_t size,
                                            std::vector<InternalVBMetaDescriptor>* descriptors) {
    for (int p = 0; p < size;) {
        InternalVBMetaDescriptor descriptor;
        memcpy(&descriptor, (char*)buffer + p, VBMETA_TABLE_DESCRIPTOR_SIZE);
        p += VBMETA_TABLE_DESCRIPTOR_SIZE;

        descriptor.partition_name =
                std::string((char*)buffer + p, descriptor.partition_name_length);
        p += descriptor.partition_name_length;

        descriptors->emplace_back(std::move(descriptor));
    }
    return true;
}

Result<bool> ReadVBMetaTable(int fd, uint64_t offset, VBMetaTable* table) {
    std::unique_ptr<uint8_t[]> header_buffer =
            std::make_unique<uint8_t[]>(VBMETA_TABLE_HEADER_SIZE);
    if (!android::base::ReadFullyAtOffset(fd, header_buffer.get(), VBMETA_TABLE_HEADER_SIZE,
                                          offset)) {
        return Error() << "Couldn't read vbmeta table header at offset " << offset;
    }

    Result<bool> rv_header = LoadAndVerifyVBMetaTableHeader(header_buffer.get(), &table->header);
    if (!rv_header) {
        return rv_header.error();
    }

    const uint64_t descriptors_offset = offset + table->header.header_size;
    std::unique_ptr<uint8_t[]> descriptors_buffer =
            std::make_unique<uint8_t[]>(table->header.descriptors_size);
    if (!android::base::ReadFullyAtOffset(fd, descriptors_buffer.get(),
                                          table->header.descriptors_size, descriptors_offset)) {
        return Error() << "Couldn't read vbmeta table descriptors at offset " << descriptors_offset;
    }

    Result<bool> rv_descriptors = LoadAndVerifyVBMetaDescriptors(
            descriptors_buffer.get(), table->header.descriptors_size, &table->descriptors);
    if (!rv_descriptors) {
        return rv_descriptors.error();
    }

    return true;
}

Result<bool> ReadPrimaryVBMetaTable(int fd, VBMetaTable* table) {
    uint64_t offset = PRIMARY_VBMETA_TABLE_OFFSET;
    Result<bool> read_vbmeta_table = ReadVBMetaTable(fd, offset, table);
    if (!read_vbmeta_table) {
        return read_vbmeta_table.error();
    }
    return true;
}

Result<bool> ReadBackupVBMetaTable(int fd, VBMetaTable* table) {
    uint64_t offset = BACKUP_VBMETA_TABLE_OFFSET;
    Result<bool> read_vbmeta_table = ReadVBMetaTable(fd, offset, table);
    if (!read_vbmeta_table) {
        return read_vbmeta_table.error();
    }
    return true;
}

}  // namespace fs_mgr
}  // namespace android
