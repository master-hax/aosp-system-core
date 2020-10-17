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

#ifdef DEBUG_OPS

void debugPrintOp_impl(const CowOperation& op, std::string msg) {
    LOG(INFO) << "\nOperation:" << msg.c_str();
    if (op.type == kCowCopyOp)
        LOG(INFO) << "\ttype:\t"
                  << "kCowCopyOp";
    else if (op.type == kCowReplaceOp)
        LOG(INFO) << "\ttype:\t"
                  << "kCowReplaceOp";
    else if (op.type == kCowZeroOp)
        LOG(INFO) << "\ttype:\t"
                  << "kZeroOp";
    else if (op.type == kCowFooterOp)
        LOG(INFO) << "\ttype:\t"
                  << "kCowFooterOp";
    else if (op.type == kCowContinuation)
        LOG(INFO) << "\ttype:\t"
                  << "kCowContinuation";
    else
        LOG(INFO) << "\ttype:\t"
                  << "unknown:" << (int)op.type;
    if (op.compression == kCowCompressNone)
        LOG(INFO) << "\tcompression:"
                  << "kCowCompressNone";
    else if (op.compression == kCowCompressGz)
        LOG(INFO) << "\tcompression:"
                  << "kCowCompressGz";
    else if (op.compression == kCowCompressBrotli)
        LOG(INFO) << "\tcompression:"
                  << "kCowCompressBrotli";
    else
        LOG(INFO) << "\tcompression:"
                  << "unknown:" << (int)op.compression;
    LOG(INFO) << "\tdata_length:\t" << op.data_length << "\n";
    LOG(INFO) << "\tnew_block:\t" << op.new_block << "\n";
    LOG(INFO) << "\tsource:\t" << op.source << "\n";
    LOG(INFO) << "\tlabel:\t" << op.label << "\n";
}
#endif

int64_t GetNextOpOffset(const CowOperation& op) {
    if (op.type == kCowReplaceOp)
        return op.data_length;
    else
        return 0;
}

}  // namespace snapshot
}  // namespace android
