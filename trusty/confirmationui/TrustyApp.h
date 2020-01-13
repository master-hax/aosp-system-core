/*
 *
 * Copyright 2019, The Android Open Source Project
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

#ifndef TEE_HAL_TRUSTY_APP_H_
#define TEE_HAL_TRUSTY_APP_H_

#include <android-base/logging.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <teeui/msg_formatting.h>
#include <trusty/tipc.h>
#include <unistd.h>

#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#define AT __FILE__ ":" << __LINE__ << ": "

namespace android {
namespace trusty {

using ::teeui::Message;
using ::teeui::msg2tuple_t;
using ::teeui::ReadStream;
using ::teeui::WriteStream;

#ifndef TEEUI_USE_STD_VECTOR
/*
 * TEEUI_USE_STD_VECTOR makes certain wire types like teeui::MsgString and
 * teeui::MsgVector be aliases for std::vector. This is required for thread safe
 * message serialization. Always compile this with -DTEEUI_USE_STD_VECTOR set in
 * CFLAGS of the HAL service.
 */
#error "Must be compiled with -DTEEUI_USE_STD_VECTOR."
#endif

/*
 * There is a hard limitation of 0x1800 bytes for the to-be-signed message size. The protocol
 * overhead is limited, so that 0x2000 is a buffer size that will be sufficient in any benign
 * mode of operation.
 */
static constexpr const size_t kSendBufferSize = 0x2000;

ssize_t TrustyRpc(int handle, const uint8_t* obegin, const uint8_t* oend, uint8_t* ibegin,
                  uint8_t* iend);

class TrustyApp {
  private:
    int handle_;
    static constexpr const int kInvalidHandle = -1;
    std::mutex mutex_;

  public:
    TrustyApp() : handle_(kInvalidHandle) {}
    ~TrustyApp() {
        if (handle_ != kInvalidHandle) {
            tipc_close(handle_);
        }
        LOG(INFO) << "Done shutting down TrustyApp";
    }

    void start(const std::string& path, const std::string& appname) {
        if (handle_ != kInvalidHandle) {
            LOG(INFO) << "TrustyApp already connected -> ignored";
            return;
        }

        handle_ = tipc_connect(path.c_str(), appname.c_str());
        if (handle_ == kInvalidHandle) {
            LOG(ERROR) << AT << "failed to connect to Trusty TA \"" << appname << "\" using dev:"
                       << "\"" << path << "\"";
        }
        LOG(INFO) << AT << "succeeded to connect to Trusty TA \"" << appname << "\"";
    }

    template <typename Request, typename Response, typename... T>
    std::tuple<int, msg2tuple_t<Response>> issueCmd(const T&... args) {
        std::unique_lock<std::mutex> lock(mutex_);

        uint8_t buffer[kSendBufferSize];
        WriteStream out(buffer);

        out = write(Request(), out, args...);
        if (!out) {
            LOG(ERROR) << AT << "send command failed: message formatting";
            return {-2, {}};
        }

        auto rc = TrustyRpc(handle_, &buffer[0], const_cast<const uint8_t*>(out.pos()), &buffer[0],
                            &buffer[kSendBufferSize]);
        if (rc < 0) return {-1, {}};

        ReadStream in(&buffer[0], rc);
        auto result = read(Response(), in);
        if (!std::get<0>(result)) {
            LOG(ERROR) << "send command failed: message parsing";
            return {-1, {}};
        }

        return {std::get<0>(result) ? 0 : -1, tuple_tail(std::move(result))};
    }

    template <typename Request, typename... T> int issueCmd(const T&... args) {
        std::unique_lock<std::mutex> lock(mutex_);

        uint8_t buffer[kSendBufferSize];
        WriteStream out(buffer);

        out = write(Request(), out, args...);
        if (!out) {
            LOG(ERROR) << AT << "send command failed: message formatting";
            return -2;
        }

        auto rc = TrustyRpc(handle_, &buffer[0], const_cast<const uint8_t*>(out.pos()), &buffer[0],
                            &buffer[kSendBufferSize]);
        if (rc < 0) {
            LOG(ERROR) << "send command failed: " << strerror(errno) << " (" << errno << ")";
            return -1;
        }

        if (rc > 0) {
            LOG(ERROR) << "Unexpected non zero length response";
            return -1;
        }
        return 0;
    }

    operator bool() const { return handle_ != kInvalidHandle; }

  private:
    int sendChunked(const uint8_t* pos, const uint8_t* end);
    uint8_t* recvChunked(uint8_t* pos, const uint8_t* end);
};

}  // namespace trusty
}  // namespace android

#endif  // TEE_HAL_TRUSTY_APP_H_
