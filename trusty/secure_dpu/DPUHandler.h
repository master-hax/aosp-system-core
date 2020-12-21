/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <android-base/logging.h>
#include <android-base/result.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <tuple>

#include "SecureDpu.h"

namespace android {
namespace trusty {
namespace secure_dpu {

using handleCb = std::function<int(uint8_t buf[], size_t size)>;

class DPUHandler {
  private:
    int handle_;
    static constexpr const int kInvalidHandle = -1;
    /*
     * This mutex serializes communication with the trusted app, not handle_.
     * Calling issueCmd during construction or deletion is undefined behavior.
     */
    std::mutex mutex_;
    handleCb sendMsgCb;

    android::base::Result<void> HandleStartSecureDisplay();
    android::base::Result<void> HandleStopSecureDisplay();
    android::base::Result<void> HandleCmd(const uint8_t in_buf[],
                                          const size_t in_size,
                                          uint8_t out_buf[],
                                          size_t &out_size);

  public:
    static constexpr const size_t maxBufferSize = 64;

    DPUHandler(handleCb cb);
    ~DPUHandler();

    android::base::Result<void> handle(const uint8_t in_buf[], const size_t in_size) {
        std::lock_guard<std::mutex> lock(mutex_);

        uint8_t out_buf[maxBufferSize];
        size_t out_size = 0;

        if (handle_ == kInvalidHandle) {
            return base::Error() << "Invalid handle";
        }

        auto result = HandleCmd(in_buf, in_size, out_buf, out_size);
        if (!result.ok()) {
            return base::Error() << "Failed to handle command";
        }

        if (sendMsgCb(out_buf, out_size)) {
            return base::Error() << "Failed to send back to dpu";
        }
        return {};
    }
};

}  // namespace secure_dpu
}  // namespace trusty
}  // namespace android
