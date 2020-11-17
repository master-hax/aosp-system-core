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

#include <string>

#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <stdint.h>
#include <trusty/coverage/tipc.h>

namespace android {
namespace trusty {
namespace coverage {

using android::base::Result;
using android::base::unique_fd;

class CoverageRecord {
  public:
    CoverageRecord(std::string tipc_dev, struct uuid* uuid);
    ~CoverageRecord();
    Result<void> Open();
    void Reset();
    void GetRawData(volatile void** begin, volatile void** end);
    void GetRawCounts(volatile uint8_t** begin, volatile uint8_t** end);
    void GetRawPCs(volatile uintptr_t** begin, volatile uintptr_t** end);
    uint64_t TotalEdgeCounts();
    Result<void> SaveToFile(const std::string& filename);

  private:
    Result<void> Rpc(coverage_client_req* req, int req_fd, coverage_client_resp* resp);

    Result<void> ParseHeader();

    std::string tipc_dev_;
    unique_fd coverage_srv_fd_;
    struct uuid uuid_;
    size_t record_len_;
    volatile void* shm_;
    size_t shm_len_;

    // Computed from header
    size_t num_counters_;
    size_t header_len_;
    size_t byte_counter_offset_;
    size_t pcs_offset_;
};

}  // namespace coverage
}  // namespace trusty
}  // namespace android
