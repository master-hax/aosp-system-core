/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <functional>
#include <memory>
#include <string>

#include <android-base/result.h>
#include <android-base/unique_fd.h>

namespace android {
namespace trusty {
namespace metrics {

using android::base::Result;
using android::base::unique_fd;

using CrashCb = std::function<void(uint64_t event_idx, std::string app_id)>;

class TrustyMetrics {
  private:
    TrustyMetrics(std::string tipc_dev, CrashCb cb);
    Result<void> Open();

    std::string tipc_dev_;
    unique_fd metrics_fd_;
    CrashCb crash_cb_;

  public:
    static std::unique_ptr<TrustyMetrics> CreateTrustyMetrics(std::string tipc_dev, CrashCb cb);

    ~TrustyMetrics();
    Result<void> RunEventLoop();

    /* These are only made public for testing */
    Result<void> RequestNextEvent();
    Result<void> HandleEvent();
};

}  // namespace metrics
}  // namespace trusty
}  // namespace android
