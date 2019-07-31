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

#include <libvbmeta/builder.h>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <openssl/sha.h>
#include <sparse/sparse.h>

#include <libvbmeta/writer.h>
#include "utility.h"

using SparsePtr = std::unique_ptr<sparse_file, decltype(&sparse_file_destroy)>;

namespace android {
namespace fs_mgr {

SuperVBMetaBuilder::SuperVBMetaBuilder() {}

SuperVBMetaBuilder::SuperVBMetaBuilder(const LpMetadata& metadata,
                                       const std::map<std::string, std::string>& images)
    : metadata_(metadata), images_(images) {}

SuperVBMetaBuilder::SuperVBMetaBuilder(const SuperVBMeta& vbmeta) {
    for (const SuperVBMetaDescriptor& descriptor : vbmeta.descriptors) {
        Add(std::string(descriptor.partition_name, descriptor.partition_name_length),
            descriptor.vbmeta_offset, descriptor.vbmeta_size);
    }
}

bool SuperVBMetaBuilder::Build() {
    for (const auto& partition : metadata_.partitions) {
        auto iter = images_.find(std::string(partition.name));
        if (iter == images_.end()) {
            continue;
        }
        if (!AddPartitionImage(partition, iter->second)) {
            return false;
        }
        images_.erase(iter);
    }
    return true;
}

bool SuperVBMetaBuilder::AddPartitionImage(const LpMetadataPartition& partition,
                                           const std::string& file) {
    android::base::unique_fd source_fd(
            TEMP_FAILURE_RETRY(open(file.c_str(), O_RDONLY | O_CLOEXEC)));
    if (source_fd < 0) {
        LERROR << "Could not open partition image: " << file;
        return false;
    }

    int fd = source_fd.get();

    SparsePtr source(sparse_file_import(source_fd, true, true), sparse_file_destroy);
    TemporaryFile tf;
    if (tf.fd < 0) {
        PERROR << "make temporary file failed";
        return false;
    }

    if (source) {
        int rv = sparse_file_write(source.get(), tf.fd, false, false, false);
        if (rv) {
            LERROR << "sparse_file_write failed with code: " << rv;
            return false;
        }
        fd = tf.fd;
    }

    uint64_t partition_size = ComputePartitionSize(metadata_, partition);

    // Writes super AVB footer to record the offset of each logical partitions' vbmeta.
    const auto [offset, size] = GetPartitionVBMetaData(metadata_, partition, fd, partition_size);
    Add(std::string(partition.name), offset, size);
    return true;
}

bool SuperVBMetaBuilder::Add(const std::string& partition_name, uint64_t vbmeta_offset,
                             uint64_t vbmeta_size) {
    vbmetas_.emplace(partition_name, std::make_pair(vbmeta_offset, vbmeta_size));
    return true;
}

bool SuperVBMetaBuilder::Delete(const std::string& partition_name) {
    vbmetas_.erase(partition_name);
    return true;
}

std::unique_ptr<SuperVBMeta> SuperVBMetaBuilder::Export() {
    std::unique_ptr<SuperVBMeta> super_vbmeta = std::make_unique<SuperVBMeta>();

    uint32_t descriptors_size = 0;

    // descriptors
    for (const auto& vbmeta : vbmetas_) {
        SuperVBMetaDescriptor descriptor;
        descriptor.vbmeta_offset = vbmeta.second.first;
        descriptor.vbmeta_size = vbmeta.second.second;
        descriptor.partition_name_length = vbmeta.first.length();
        descriptor.partition_name = (char*)malloc(sizeof(char) * descriptor.partition_name_length);
        strcpy(descriptor.partition_name, vbmeta.first.c_str());
        memset(descriptor.reserved, 0, sizeof(descriptor.reserved));
        super_vbmeta->descriptors.emplace_back(std::move(descriptor));

        descriptors_size +=
                SUPER_VBMETA_DESCRIPTOR_SIZE + descriptor.partition_name_length * sizeof(char);
    }

    // header
    super_vbmeta->header.magic = SUPER_VBMETA_MAGIC;
    super_vbmeta->header.major_version = SUPER_VBMETA_MAJOR_VERSION;
    super_vbmeta->header.minor_version = SUPER_VBMETA_MINOR_VERSION;
    super_vbmeta->header.header_size = SUPER_VBMETA_HEADER_SIZE;
    super_vbmeta->header.total_size = SUPER_VBMETA_HEADER_SIZE + descriptors_size;
    memset(super_vbmeta->header.checksum, 0, sizeof(super_vbmeta->header.checksum));
    super_vbmeta->header.descriptors_size = descriptors_size;
    std::string serial = SerializeSuperVBMeta(*super_vbmeta);
    ::SHA256(reinterpret_cast<const uint8_t*>(serial.c_str()), super_vbmeta->header.total_size,
             super_vbmeta->header.checksum);
    return super_vbmeta;
}

bool SuperVBMetaBuilder::Export(const std::string& file) {
    android::base::unique_fd fd(
            TEMP_FAILURE_RETRY(open(file.c_str(), O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644)));
    if (fd.get() < 0) {
        LERROR << "Could not export super vbmeta in " << file;
        return false;
    }

    std::unique_ptr<SuperVBMeta> vbmeta = Export();

    std::string serialized_vbmeta = SerializeSuperVBMeta(*vbmeta.get());

    if (!WritePrimaryVBMeta(fd.get(), serialized_vbmeta)) {
        LERROR << "write super primary VBMeta failed\n";
    }

    if (!WriteBackupVBMeta(fd.get(), serialized_vbmeta)) {
        LERROR << "write super backup VBMeta failed\n";
    }

    return true;
}

bool WriteToVBMetaFile(const std::string& file, const LpMetadata& metadata,
                       const std::map<std::string, std::string>& images) {
    SuperVBMetaBuilder builder(metadata, images);
    return builder.Build() && builder.Export(file);
}

}  // namespace fs_mgr
}  // namespace android