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

int64_t GetNextOpOffset(const CowOperation& op, uint32_t cluster_size) {
    if (op.type == kCowClusterOp)
        return op.source;
    else if (op.type == kCowReplaceOp && cluster_size == 0)
        return op.data_length;
    else
        return 0;
}

int64_t GetNextDataOffset(const CowOperation& op, uint32_t cluster_size) {
    if (op.type == kCowClusterOp)
        return cluster_size;
    else if (cluster_size == 0)
        return sizeof(CowOperation);
    else
        return 0;
}

bool validateOp(const CowOperation& op) {
    if (op.type != kCowCopyOp && op.type != kCowReplaceOp && op.type != kCowZeroOp &&
        op.type != kCowFooterOp && op.type != kCowLabelOp && op.type != kCowClusterOp &&
        op.type != kCowFooterOp) {
        return false;
    }
    // zero ops must have source set to 0.
    if (op.type == kCowZeroOp && op.source != 0) return false;

    // Footer must have data length for the footer data. Otherwise, only CowReplaceOp has data
    // associated
    if (op.type == kCowFooterOp) {
        if (op.data_length != sizeof(CowFooterData)) return false;
    } else if (op.type != kCowReplaceOp && op.data_length > 0) {
        return false;
    }

    if (op.type != kCowReplaceOp && op.data_length > 0) return false;
    // footer must have space for footer data

    return true;
}

}  // namespace snapshot
}  // namespace android
