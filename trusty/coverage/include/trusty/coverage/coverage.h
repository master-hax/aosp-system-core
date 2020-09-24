/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <stdint.h>
#include <trusty/coverage/tipc.h>

namespace android {
namespace trusty {

class CoverageRecord {
  public:
    CoverageRecord(struct uuid* uuid, size_t shm_len);
    ~CoverageRecord();
    android::base::Result<void> Open();
    android::base::Result<void> Pull();
    android::base::Result<void> Reset();
    android::base::Result<void> GetRawData(volatile void** begin, volatile void** end);
    android::base::Result<uint64_t> CountBlocks();

  private:
    android::base::Result<void> RegisterShm(android::base::unique_fd memfd);
    android::base::Result<void> RemoteOp(uint32_t cmd);

    struct uuid uuid_;
    volatile void* shm_;
    size_t shm_len_;
    size_t data_len_;
    android::base::unique_fd coverage_srv_fd_;
};

}  // namespace trusty
}  // namespace android
