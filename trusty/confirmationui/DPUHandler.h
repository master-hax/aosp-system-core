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
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <tuple>

#include <secure_dpu/secure_dpu_proto.h>

namespace android {
namespace dpu_handler {

enum class HandleCmdResult : uint32_t {
    Fail,
    Success,
    Abort,
};

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

    std::tuple<HandleCmdResult, std::string> handleCmd(uint8_t buf[], size_t& size);

  public:
    static constexpr const size_t maxBufferSize = 64;

    DPUHandler(handleCb cb);
    ~DPUHandler();

    std::tuple<int, std::string> handle(uint8_t buf[], size_t size) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (handle_ == kInvalidHandle) {
            return {-1, "Invalied handler"};
        }

        auto [rc, err_msg] = handleCmd(buf, size);
        switch (rc) {
            case HandleCmdResult::Fail:
                return {-1, err_msg};
            case HandleCmdResult::Abort:
                return {0, err_msg};
            case HandleCmdResult::Success:
                break;
        }

        if (sendMsgCb(buf, size)) {
            return {-1, "Failed to send back to dpu"};
        }
        return {0, {}};
    }
};

}  // namespace dpu_handler
}  // namespace android
