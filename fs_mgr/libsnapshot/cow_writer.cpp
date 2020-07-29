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

#include <sys/types.h>
#include <unistd.h>

#include <string_view>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <libsnapshot/cow_writer.h>
#include <openssl/sha.h>

namespace android {
namespace snapshot {

static_assert(sizeof(off_t) == sizeof(uint64_t));

CowWriter::CowWriter(const CowOptions& options, android::base::unique_fd&& fd)
    : ICowWriter(options), owned_fd_(std::move(fd)), fd_(owned_fd_) {
    SetupHeaders();
}

CowWriter::CowWriter(const CowOptions& options, android::base::borrowed_fd fd)
    : ICowWriter(options), fd_(fd) {
    SetupHeaders();
}

void CowWriter::SetupHeaders() {
    header_ = {};
    header_.magic = kCowMagicNumber;
    header_.major_version = kCowVersionMajor;
    header_.minor_version = kCowVersionMinor;
    header_.block_size = options_.block_size;
}

bool CowWriter::Initialize() {
    if (lseek(fd_.get(), SEEK_SET, 0) < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }

    // Headers are not complete, but this ensures the file is at the right
    // position.
    if (!android::base::WriteFully(fd_, &header_, sizeof(header_))) {
        PLOG(ERROR) << "write failed";
        return false;
    }
    return true;
}

bool CowWriter::AddCopy(uint64_t new_block, uint64_t old_block) {
    header_.num_ops++;

    CowOperation op;
    op.op = kCowCopyOp;
    op.new_block = new_block;
    op.source = old_block;
    ops_ << std::string_view(reinterpret_cast<char*>(&op), sizeof(op));

    return true;
}

bool CowWriter::AddRawBlocks(uint64_t new_block_start, const void* data, size_t size) {
    if (size % header_.block_size != 0) {
        LOG(ERROR) << "AddRawBlocks: size " << size << " is not a multiple of "
                   << header_.block_size;
        return false;
    }

    uint64_t pos;
    if (!GetDataPos(&pos)) {
        return false;
    }

    const uint8_t* iter = reinterpret_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size / header_.block_size; i++) {
        header_.num_ops++;

        CowOperation op;
        op.op = kCowReplaceOp;
        op.new_block = new_block_start + i;
        op.source = pos;
        ops_ << std::string_view(reinterpret_cast<char*>(&op), sizeof(op));

        pos += header_.block_size;
        iter += header_.block_size;
    }

    if (!android::base::WriteFully(fd_, data, size)) {
        PLOG(ERROR) << "AddRawBlocks: write failed";
        return false;
    }
    return true;
}

static void SHA256(const void* data, size_t length, uint8_t out[32]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, length);
    SHA256_Final(out, &c);
}

bool CowWriter::Finalize() {
    std::string op_data = ops_.str();
    ops_.clear();

    auto offs = lseek(fd_.get(), SEEK_CUR, 0);
    if (offs < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }
    header_.ops_offset = offs;
    header_.ops_size = op_data.size();

    SHA256(op_data.data(), op_data.size(), header_.ops_checksum);
    SHA256(&header_, sizeof(header_), header_.header_checksum);

    if (lseek(fd_.get(), SEEK_SET, 0) < 0) {
        PLOG(ERROR) << "lseek start failed";
        return false;
    }
    if (!android::base::WriteFully(fd_, &header_, sizeof(header_))) {
        PLOG(ERROR) << "write header failed";
        return false;
    }
    if (lseek(fd_.get(), SEEK_SET, header_.ops_offset) < 0) {
        PLOG(ERROR) << "lseek ops failed";
        return false;
    }
    if (!android::base::WriteFully(fd_, op_data.data(), op_data.size())) {
        PLOG(ERROR) << "write ops failed";
        return false;
    }
    return true;
}

bool CowWriter::GetDataPos(uint64_t* pos) {
    off_t offs = lseek(fd_.get(), SEEK_CUR, 0);
    if (offs < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }
    *pos = offs;
    return true;
}

}  // namespace snapshot
}  // namespace android
