//
// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <unordered_set>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <libsnapshot/cow_writer.h>
#include <update_engine/update_metadata.pb.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;
using chromeos_update_engine::DeltaArchiveManifest;
using chromeos_update_engine::Extent;
using chromeos_update_engine::InstallOperation;
using chromeos_update_engine::PartitionUpdate;

void MyLogger(android::base::LogId, android::base::LogSeverity severity, const char*, const char*,
              unsigned int, const char* message) {
    if (severity == android::base::ERROR) {
        fprintf(stderr, "%s\n", message);
    } else {
        fprintf(stdout, "%s\n", message);
    }
}

uint64_t ToLittleEndian(uint64_t value) {
    union {
        uint64_t u64;
        char bytes[8];
    } packed;
    packed.u64 = value;
    std::swap(packed.bytes[0], packed.bytes[7]);
    std::swap(packed.bytes[1], packed.bytes[6]);
    std::swap(packed.bytes[2], packed.bytes[5]);
    std::swap(packed.bytes[3], packed.bytes[4]);
    return packed.u64;
}

class PayloadConverter final {
  public:
    PayloadConverter(const std::string& in_file, const std::string& out_dir)
        : in_file_(in_file), out_dir_(out_dir) {}

    bool Run();

  private:
    bool OpenPayload();
    bool ProcessPartition(const PartitionUpdate& update);
    bool ProcessOperation(const InstallOperation& op);
    bool ProcessZero(const InstallOperation& op);
    bool ProcessCopy(const InstallOperation& op);

    std::string in_file_;
    std::string out_dir_;
    android::base::unique_fd in_fd_;
    uint64_t payload_offset_ = 0;
    DeltaArchiveManifest manifest_;
    std::unordered_set<std::string> dap_;
    std::unique_ptr<CowWriter> writer_;
};

bool PayloadConverter::Run() {
    if (!OpenPayload()) {
        return false;
    }

    if (manifest_.has_dynamic_partition_metadata()) {
        const auto& dpm = manifest_.dynamic_partition_metadata();
        for (const auto& group : dpm.groups()) {
            for (const auto& partition : group.partition_names()) {
                dap_.emplace(partition);
            }
        }
    }

    if (dap_.empty()) {
        LOG(ERROR) << "No dynamic partitions found.";
        return false;
    }

    for (const auto& update : manifest_.partitions()) {
        if (!ProcessPartition(update)) {
            return false;
        }
        writer_ = nullptr;
    }
    return true;
}

bool PayloadConverter::ProcessPartition(const PartitionUpdate& update) {
    auto partition_name = update.partition_name();
    if (dap_.find(partition_name) == dap_.end()) {
        // Skip non-DAP partitions.
        return true;
    }

    auto path = out_dir_ + "/" + partition_name + ".cow";
    unique_fd fd(open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
    if (fd < 0) {
        PLOG(ERROR) << "open failed: " << path;
        return false;
    }

    CowOptions options;
    writer_ = std::make_unique<CowWriter>(options);
    if (!writer_->Initialize(std::move(fd))) {
        LOG(ERROR) << "Unable to initialize COW writer";
        return false;
    }

    for (const auto& op : update.operations()) {
        if (!ProcessOperation(op)) {
            return false;
        }
    }

    if (!writer_->Finalize()) {
        LOG(ERROR) << "Unable to finalize COW for " << partition_name;
        return false;
    }
    return true;
}

bool PayloadConverter::ProcessOperation(const InstallOperation& op) {
    switch (op.type()) {
        case InstallOperation::SOURCE_COPY:
            if (!ProcessCopy(op)) return false;
            break;
        case InstallOperation::BROTLI_BSDIFF:
        case InstallOperation::PUFFDIFF:
            break;
        case InstallOperation::REPLACE_XZ:
        case InstallOperation::REPLACE_BZ:
            break;
        case InstallOperation::ZERO:
            if (!ProcessZero(op)) return false;
            break;
        default:
            LOG(ERROR) << "Unsupported op: " << (int)op.type();
            return false;
    }
    return true;
}

bool PayloadConverter::ProcessZero(const InstallOperation& op) {
    for (const auto& extent : op.dst_extents()) {
        if (!writer_->AddZeroBlocks(extent.start_block(), extent.num_blocks())) {
            LOG(ERROR) << "Could not add zero operation";
            return false;
        }
    }
    return true;
}

bool PayloadConverter::ProcessCopy(const InstallOperation& op) {
    auto dst_iter = op.dst_extents().begin();
    uint64_t dst_index = 0;

    auto next_dst_block = [&](uint64_t* out) -> bool {
        while (dst_iter != op.dst_extents().end()) {
            if (dst_index < dst_iter->num_blocks()) {
                break;
            }
            dst_iter++;
            dst_index = 0;
        }
        if (dst_iter == op.dst_extents().end()) {
            return false;
        }
        *out = dst_iter->start_block() + dst_index;
        dst_index++;
        return true;
    };

    for (const auto& extent : op.src_extents()) {
        for (uint64_t i = 0; i < extent.num_blocks(); i++) {
            uint64_t src_block = extent.start_block() + i;
            uint64_t dst_block;
            if (!next_dst_block(&dst_block)) {
                LOG(ERROR) << "SOURCE_COPY contained mismatching extents";
                return false;
            }
            if (src_block == dst_block) continue;
            if (!writer_->AddCopy(dst_block, src_block)) {
                LOG(ERROR) << "Could not add copy operation";
                return false;
            }
        }
    }
    return true;
}

bool PayloadConverter::OpenPayload() {
    in_fd_.reset(open(in_file_.c_str(), O_RDONLY));
    if (in_fd_ < 0) {
        PLOG(ERROR) << "open " << in_file_;
        return false;
    }

    char magic[4];
    if (!android::base::ReadFully(in_fd_, magic, sizeof(magic))) {
        PLOG(ERROR) << "read magic";
        return false;
    }
    if (std::string(magic, sizeof(magic)) != "CrAU") {
        LOG(ERROR) << "Invalid magic in " << in_file_;
        return false;
    }

    uint64_t version;
    uint64_t manifest_size;
    uint32_t manifest_signature_size = 0;
    if (!android::base::ReadFully(in_fd_, &version, sizeof(version))) {
        PLOG(ERROR) << "read version";
        return false;
    }
    version = ToLittleEndian(version);
    if (version < 2) {
        LOG(ERROR) << "Only payload version 2 or higher is supported.";
        return false;
    }

    if (!android::base::ReadFully(in_fd_, &manifest_size, sizeof(manifest_size))) {
        PLOG(ERROR) << "read manifest_size";
        return false;
    }
    manifest_size = ToLittleEndian(manifest_size);
    if (!android::base::ReadFully(in_fd_, &manifest_signature_size,
                                  sizeof(manifest_signature_size))) {
        PLOG(ERROR) << "read manifest_signature_size";
        return false;
    }
    manifest_signature_size = ntohl(manifest_signature_size);

    auto manifest = std::make_unique<uint8_t[]>(manifest_size);
    if (!android::base::ReadFully(in_fd_, manifest.get(), manifest_size)) {
        PLOG(ERROR) << "read manifest";
        return false;
    }

    // Skip past manifest signature.
    auto offs = lseek(in_fd_, manifest_signature_size, SEEK_CUR);
    if (offs < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }
    payload_offset_ = offs;

    if (!manifest_.ParseFromArray(manifest.get(), manifest_size)) {
        LOG(ERROR) << "could not parse manifest";
        return false;
    }
    return true;
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    android::base::InitLogging(argv, android::snapshot::MyLogger);

    if (argc < 3) {
        std::cerr << "Usage: <payload.bin> <out-dir>\n";
        return 1;
    }

    android::snapshot::PayloadConverter pc(argv[1], argv[2]);
    return pc.Run() ? 0 : 1;
}
