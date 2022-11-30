/*
 * Copyright (C) 2022 The Android Open Source Project
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

#pragma once

#include <cstdint>

#include <android-base/result.h>
#include <android-base/unique_fd.h>

namespace android {
namespace init {

// Memory region that can be shared between processes.
class SharedMemory {
  public:
    using unique_fd = android::base::unique_fd;
    template <typename T>
    using Result = android::base::Result<T>;

    explicit SharedMemory(uint32_t size);
    SharedMemory(const SharedMemory&) = delete;
    SharedMemory& operator=(const SharedMemory&) = delete;
    ~SharedMemory();
    Result<void> CreateMemfd();
    Result<void*> Map();
    void* MappedAt() const { return addr_; }
    Result<void> Unmap();

  private:
    uint32_t size_;
    unique_fd memfd_;
    void* addr_;
};

}  // namespace init
}  // namespace android
