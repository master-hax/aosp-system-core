//
// Copyright (C) 2023 The Android Open Source Project
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
#include <memory>

#include <array>
#include <iostream>
#include <random>

#include <libsnapshot/cow_compress.h>
#include <libsnapshot/cow_format.h>

#include <gflags/gflags.h>
#include <iostream>

static const uint32_t BLOCK_SZ = 4096;
static const uint32_t SEED_NUMBER = 10;

namespace android {
namespace snapshot {

// static std::string CompressionToString(CowCompression& compression) {
//     std::string output;
//     switch (compression.algorithm) {
//         case kCowCompressBrotli:
//             output.append("brotli");
//             break;
//         case kCowCompressGz:
//             output.append("gz");
//             break;
//         case kCowCompressLz4:
//             output.append("lz4");
//             break;
//         case kCowCompressZstd:
//             output.append("zstd");
//             break;
//         case kCowCompressNone:
//             return "No Compression";
//     }
//     output.append(" " + std::to_string(compression.compression_level));
//     return output;
// }

void CompressionTest() {
    std::cout << "\n-------One Shot Compressor Perf Analysis-------\n";

    // // Allocate a buffer of size 1024 blocks.
    // std::array<char, 4096 * 1024> buffer;

    // // Generate a random 4k buffer of characters
    // std::default_random_engine gen(SEED_NUMBER);
    // std::uniform_int_distribution<int> distribution(0, 5);
    // for (int i = 0; i < buffer.size(); i++) {
    //     buffer[i] = static_cast<char>(distribution(gen));
    // }

    // std::vector<std::pair<double, std::string>> latencies;
    // std::vector<std::pair<double, std::string>> ratios;
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    if (argc < 2) {
        gflags::ShowUsageWithFlags(argv[0]);
        return 1;
    }
    android::snapshot::CompressionTest();
    return 0;
}