// Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <stdint.h>

namespace android {
namespace snapshot {

static constexpr int kNumScratchBuffers = 8;
static constexpr int kScratchBufferSize = (1UL << 20);
static constexpr int kMaxQueueProcessingSize = 512;
static constexpr uint8_t kDrainQueue = 0xff;

struct WriteEntry {
    uint8_t op_type;
    void* scratch_buffer;
    uint64_t new_block;
    uint64_t source;
    std::vector<std::unique_ptr<uint8_t[]>> buffer_vec_;

    WriteEntry() : scratch_buffer(nullptr) {}
};

}  // namespace snapshot
}  // namespace android
