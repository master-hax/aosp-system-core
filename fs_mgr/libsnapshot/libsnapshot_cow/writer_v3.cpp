//
// Copyright (C) 2020 The Android Open Source_info Project
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

#include "writer_v3.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <brotli/encode.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <lz4.h>
#include <zlib.h>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "android-base/parseint.h"
#include "android-base/strings.h"

// The info messages here are spammy, but as useful for update_engine. Disable
// them when running on the host.
#ifdef __ANDROID__
#define LOG_INFO LOG(INFO)
#else
#define LOG_INFO LOG(VERBOSE)
#endif

namespace android {
namespace snapshot {

static_assert(sizeof(off_t) == sizeof(uint64_t));

using android::base::unique_fd;

CowWriterV3::CowWriterV3(const CowOptions& options, unique_fd&& fd)
    : CowWriterBase(options, std::move(fd)) {
    SetupHeaders();
    SetupWriteOptions();
}

void CowWriterV3::SetupHeaders() {
    header_ = {};
    header_.prefix.magic = kCowMagicNumber;
    header_.prefix.major_version = kCowVersionMajor;
    header_.prefix.minor_version = kCowVersionMinor;
    header_.prefix.header_size = sizeof(CowHeader);
    header_.footer_size = sizeof(CowFooter);
    header_.op_size = sizeof(CowOperationV3);
    header_.block_size = options_.block_size;
    header_.num_merge_ops = options_.num_merge_ops;
    header_.cluster_ops = options_.cluster_ops;
    header_.buffer_size = 0;
    header_.compression_algorithm = 0;
    footer_ = {};
    footer_.op.data_length = 64;
    footer_.op.type = kCowFooterOp;
}

void CowWriterV3::SetupWriteOptions() {
    num_compress_threads_ = options_.num_compress_threads;

    if (!num_compress_threads_) {
        num_compress_threads_ = 1;
        // We prefer not to have more than two threads as the overhead of additional
        // threads is far greater than cutting down compression time.
        if (header_.cluster_ops &&
            android::base::GetBoolProperty("ro.virtual_ab.compression.threads", false)) {
            num_compress_threads_ = 2;
        }
    }

    if (header_.cluster_ops &&
        (android::base::GetBoolProperty("ro.virtual_ab.batch_writes", false) ||
         options_.batch_write)) {
        batch_write_ = true;
    }
}

CowWriterV3::~CowWriterV3() {}

bool CowWriterV3::ParseOptions() {
    auto parts = android::base::Split(options_.compression, ",");

    if (parts.size() > 2) {
        LOG(ERROR) << "failed to parse compression parameters: invalid argument count: "
                   << parts.size() << " " << options_.compression;
        return false;
    }
    auto algorithm = CompressionAlgorithmFromString(parts[0]);
    if (!algorithm) {
        LOG(ERROR) << "unrecognized compression: " << options_.compression;
        return false;
    }
    header_.compression_algorithm = static_cast<int>(algorithm.value());
    if (parts.size() > 1) {
        if (!android::base::ParseUint(parts[1], &compression_.compression_level)) {
            LOG(ERROR) << "failed to parse compression level invalid type: " << parts[1];
            return false;
        }
    } else {
        compression_.compression_level =
                CompressWorker::GetDefaultCompressionLevel(algorithm.value());
    }

    compression_.algorithm = *algorithm;

    if (options_.cluster_ops == 1) {
        LOG(ERROR) << "Clusters must contain at least two operations to function.";
        return false;
    }
    return true;
}

bool CowWriterV3::Initialize() {
    if (!InitFd() || !ParseOptions()) {
        return false;
    }

    // FIXME: Add Parse Resume Logic. If we have a resume point, we call OpenForAppend, otherwise
    // OpenForWrite()

    //  if (!label) {
    //      if (!OpenForWrite()) {
    //          return false;
    //      }
    //  } else {
    //      if (!OpenForAppend(*label)) {
    //          return false;
    //      }
    //  }

    // if (!compress_threads_.size()) {
    //     InitWorkers();
    // }
    return true;
}

void CowWriterV3::InitBatchWrites() {
    return;
}

void CowWriterV3::InitWorkers() {
    return;
}

void CowWriterV3::InitPos() {
    return;
}

bool CowWriterV3::OpenForWrite() {
    return true;
}

bool CowWriterV3::OpenForAppend(uint64_t label) {
    if (label) return false;
    return true;
}

bool CowWriterV3::EmitCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks) {
    if (new_block || old_block || num_blocks) return true;
    return true;
}

bool CowWriterV3::EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) {
    return EmitBlocks(new_block_start, data, size, 0, 0, kCowReplaceOp);
}

bool CowWriterV3::EmitXorBlocks(uint32_t new_block_start, const void* data, size_t size,
                                uint32_t old_block, uint16_t offset) {
    return EmitBlocks(new_block_start, data, size, old_block, offset, kCowXorOp);
}

bool CowWriterV3::CompressBlocks(size_t num_blocks, const void* data) {
    if (num_blocks && data) return true;
    return true;
}

bool CowWriterV3::EmitBlocks(uint64_t new_block_start, const void* data, size_t size,
                             uint64_t old_block, uint16_t offset, uint8_t type) {
    if (new_block_start && data && size && old_block && offset && type) return true;
    return true;
}

bool CowWriterV3::EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) {
    if (new_block_start && num_blocks) return true;
    return true;
}

bool CowWriterV3::EmitLabel(uint64_t label) {
    if (label) return false;
    return true;
}

bool CowWriterV3::EmitSequenceData(size_t num_ops, const uint32_t* data) {
    if (num_ops && data) return true;
    return true;
}

bool CowWriterV3::EmitCluster() {
    return true;
}

bool CowWriterV3::EmitClusterIfNeeded() {
    return true;
}

bool CowWriterV3::Finalize() {
    return true;
}

uint64_t CowWriterV3::GetCowSize() {
    return true;
}

bool CowWriterV3::GetDataPos(uint64_t* pos) {
    if (pos) return true;
    return true;
}

bool CowWriterV3::EnsureSpaceAvailable(const uint64_t bytes_needed) const {
    if (bytes_needed) return true;
    return true;
}

bool CowWriterV3::FlushCluster() {
    return true;
}

bool CowWriterV3::WriteOperation(const CowOperationV3& op, const void* data, size_t size) {
    if (op.data_length && data && size) return true;
    return false;
}

void CowWriterV3::AddOperation(const CowOperationV3& op) {
    if (op.data_length) return;
    return;
}

bool CowWriterV3::WriteRawData(const void* data, const size_t size) {
    if (data && size) return true;
    return true;
}

bool CowWriterV3::Sync() {
    return true;
}

bool CowWriterV3::Truncate(off_t length) {
    return length ? true : false;
}

}  // namespace snapshot
}  // namespace android
