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

using CrashCb = std::function<void(std::string app_id)>;
using EventDropCb = std::function<void()>;

class TrustyMetrics {
  private:
    TrustyMetrics(std::string tipc_dev, CrashCb crash_cb, EventDropCb event_drop_cb)
        : tipc_dev_(std::move(tipc_dev)),
          metrics_fd_(-1),
          crash_cb_(std::move(crash_cb)),
          event_drop_cb_(std::move(event_drop_cb)) {}

    Result<void> Open();

    std::string tipc_dev_;
    unique_fd metrics_fd_;

    CrashCb crash_cb_;
    EventDropCb event_drop_cb_;

  public:
    static std::unique_ptr<TrustyMetrics> CreateTrustyMetrics(std::string tipc_dev,
                                                              CrashCb crash_cb,
                                                              EventDropCb event_drop_cb);

    ~TrustyMetrics(){};
    Result<void> RunEventLoop();

    /* Only made public for testing */
    Result<void> HandleEvent();
};

}  // namespace metrics
}  // namespace trusty
}  // namespace android
