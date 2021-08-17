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

#include <libsnapshot/cow_format.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/logging.h>

namespace android {
namespace snapshot {

std::ostream& operator<<(std::ostream& os, CowOperation const& op) {
    os << "CowOperation(type:";
    if (op.type == kCowCopyOp)
        os << "kCowCopyOp,    ";
    else if (op.type == kCowReplaceOp)
        os << "kCowReplaceOp, ";
    else if (op.type == kCowZeroOp)
        os << "kZeroOp,       ";
    else if (op.type == kCowFooterOp)
        os << "kCowFooterOp,  ";
    else if (op.type == kCowLabelOp)
        os << "kCowLabelOp,   ";
    else if (op.type == kCowClusterOp)
        os << "kCowClusterOp  ";
    else if (op.type == kCowXorOp)
        os << "kCowXorOp      ";
    else if (op.type == kCowSequenceOp)
        os << "kCowSequenceOp ";
    else if (op.type == kCowFooterOp)
        os << "kCowFooterOp  ";
    else
        os << (int)op.type << "?,";
    os << "compression:";
    if (op.compression == kCowCompressNone)
        os << "kCowCompressNone,   ";
    else if (op.compression == kCowCompressGz)
        os << "kCowCompressGz,     ";
    else if (op.compression == kCowCompressBrotli)
        os << "kCowCompressBrotli, ";
    else
        os << (int)op.compression << "?, ";
    os << "data_length:" << op.data_length << ",\t";
    os << "new_block:" << op.new_block << ",\t";
    os << "source:" << op.source << ")";
    return os;
}

const CowOperation* checkLegacyOp(CowOp* op, uint8_t* data, size_t len) {
    if (op->getOpLength() > len) return nullptr;
    const CowOperation* raw_op = reinterpret_cast<const CowOperation*>(data);
    if (raw_op->type != op->getType()) return nullptr;
    return raw_op;
}

const std::vector<uint8_t> exportLegacyOp(CowOperation& op) {
    std::vector<uint8_t> data;
    data.resize(sizeof(CowOperation));
    memcpy(data.data(), &op, sizeof(CowOperation));
    return data;
}

bool LegacyCowCopyOp::importOp(uint8_t* data, size_t len) {
    const CowOperation* op = checkLegacyOp(this, data, len);
    if (!op) return false;

    new_block_ = (uint32_t)op->new_block;
    source_block_ = (uint32_t)op->source;
    return true;
}

std::vector<uint8_t> LegacyCowCopyOp::exportOp() const {
    CowOperation op = {};
    op.type = getType();
    op.new_block = new_block_;
    op.source = source_block_;

    return exportLegacyOp(op);
}

bool LegacyCowReplaceOp::importOp(uint8_t* data, size_t len) {
    const CowOperation* op = checkLegacyOp(this, data, len);
    if (!op) return false;

    new_block_ = (uint32_t)op->new_block;
    data_length_ = op->data_length;
    compression_ = op->compression;
    return true;
}

std::vector<uint8_t> LegacyCowReplaceOp::exportOp() const {
    CowOperation op = {};
    op.type = getType();
    op.new_block = new_block_;
    op.source = data_loc_;
    op.compression = compression_;

    return exportLegacyOp(op);
}

bool LegacyCowZeroOp::importOp(uint8_t* data, size_t len) {
    const CowOperation* op = checkLegacyOp(this, data, len);
    if (!op) return false;

    new_block_ = (uint32_t)op->new_block;
    return true;
}

std::vector<uint8_t> LegacyCowZeroOp::exportOp() const {
    CowOperation op = {};
    op.type = getType();
    op.new_block = new_block_;

    return exportLegacyOp(op);
}

bool LegacyCowLabelOp::importOp(uint8_t* data, size_t len) {
    const CowOperation* op = checkLegacyOp(this, data, len);
    if (!op) return false;

    label_ = op->source;
    return true;
}

std::vector<uint8_t> LegacyCowLabelOp::exportOp() const {
    CowOperation op = {};
    op.type = getType();
    op.source = label_;

    return exportLegacyOp(op);
}

bool LegacyCowClusterOp::importOp(uint8_t* data, size_t len) {
    const CowOperation* op = checkLegacyOp(this, data, len);
    if (!op) return false;

    next_cluster_ = op->source;
    return true;
}

std::vector<uint8_t> LegacyCowClusterOp::exportOp() const {
    CowOperation op = {};
    op.type = getType();
    op.source = getNextClusterStart();

    return exportLegacyOp(op);
}

bool LegacyCowXorOp::importOp(uint8_t* data, size_t len) {
    const CowOperation* op = checkLegacyOp(this, data, len);
    if (!op) return false;

    new_block_ = (uint32_t)op->new_block;
    data_length_ = op->data_length;
    compression_ = op->compression;
    offset_ = op->source;
    return true;
}

std::vector<uint8_t> LegacyCowXorOp::exportOp() const {
    CowOperation op = {};
    op.type = getType();
    op.new_block = new_block_;
    op.data_length = data_length_;
    op.compression = compression_;
    op.source = offset_;

    return exportLegacyOp(op);
}

bool LegacyCowSequenceOp::importOp(uint8_t* data, size_t len) {
    const CowOperation* op = checkLegacyOp(this, data, len);
    if (!op) return false;

    data_length_ = op->data_length;
    data_loc_ = op->source;
    return true;
}

std::vector<uint8_t> LegacyCowSequenceOp::exportOp() const {
    CowOperation op = {};
    op.type = getType();
    op.data_length = data_length_;
    op.source = data_loc_;

    return exportLegacyOp(op);
}

int64_t GetNextOpOffset(const CowOperation& op, uint32_t cluster_ops) {
    if (op.type == kCowClusterOp) {
        return op.source;
    } else if ((op.type == kCowReplaceOp || op.type == kCowXorOp) && cluster_ops == 0) {
        return op.data_length;
    } else {
        return 0;
    }
}

int64_t GetNextDataOffset(const CowOperation& op, uint32_t cluster_ops) {
    if (op.type == kCowClusterOp) {
        return cluster_ops * sizeof(CowOperation);
    } else if (cluster_ops == 0) {
        return sizeof(CowOperation);
    } else {
        return 0;
    }
}

int64_t GetNextOpOffsetC(const CowOp& op, uint32_t cluster_ops) {
    if (op.getType() == kCowClusterOp) {
        return static_cast<const CowClusterOp&>(op).getNextClusterStart();
    } else if (cluster_ops == 0) {
        return op.getDataLength();
    } else {
        return 0;
    }
}

int64_t GetNextDataOffsetC(const CowOp& op, uint32_t cluster_ops) {
    if (op.getType() == kCowClusterOp) {
        return cluster_ops * sizeof(CowOperation);
    } else if (cluster_ops == 0) {
        return op.getOpLength();
    } else {
        return 0;
    }
}

bool IsMetadataOp(const CowOperation& op) {
    switch (op.type) {
        case kCowLabelOp:
        case kCowClusterOp:
        case kCowFooterOp:
        case kCowSequenceOp:
            return true;
        default:
            return false;
    }
}

bool IsOrderedOp(const CowOperation& op) {
    switch (op.type) {
        case kCowCopyOp:
        case kCowXorOp:
            return true;
        default:
            return false;
    }
}

}  // namespace snapshot
}  // namespace android
