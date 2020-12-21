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
#include <tuple>

namespace android {
namespace proxy_handler {

using handleCb = std::function<int(uint8_t buf[], size_t size)>;

class ProxyHandler {
  private:
    int handle_;
    static constexpr const int kInvalidHandle = -1;
    /*
     * This mutex serializes communication with the trusted app, not handle_.
     * Calling issueCmd during construction or deletion is undefined behavior.
     */
    std::mutex mutex_;

    void handleCmd(uint8_t buf[], size_t& size);

  public:
    static constexpr const size_t maxBufferSize = 64;
    ProxyHandler();
    ~ProxyHandler();
    int handle(uint8_t buf[], size_t size, handleCb cb) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (handle_ == kInvalidHandle) {
            LOG(ERROR) << "Invalid handle to proxy handler";
            return -1;
        }

        handleCmd(buf, size);

        if (cb(buf, size)) {
            LOG(ERROR) << "failed to send back to proxy";
            return -1;
        }
        return 0;
    }
};

}  // namespace proxy_handler
}  // namespace android
