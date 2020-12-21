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

    HandleCmdResult HandleAllocateBuffer(const uint64_t req_buffer_len, struct secure_dpu_allocate_buffer_rsp* args);
    HandleCmdResult HandleFreeBuffer(const uint64_t req_buffer_ptr, const uint64_t req_buffer_len);
    HandleCmdResult HandleStartSecureDisplay();
    HandleCmdResult HandleStopSecureDisplay();

    std::tuple<HandleCmdResult, std::string> handleCmd(const uint8_t in_buf[], const size_t in_size, uint8_t out_buf[], size_t &out_size) {
          if (in_size < sizeof(struct secure_dpu_req)) {
              return {HandleCmdResult::Fail, "Invalid payload"};
          }
          const struct secure_dpu_req* req = reinterpret_cast<const struct secure_dpu_req*>(in_buf);
          switch (req->cmd) {
              case SECURE_DPU_CMD_ALLOCATE_BUFFER: {
                  if (in_size != sizeof(struct secure_dpu_req) + sizeof(struct secure_dpu_allocate_buffer_req)) {
                      return {HandleCmdResult::Fail, "Invalid payload"};
                  }
                  const struct secure_dpu_allocate_buffer_req* req_args = reinterpret_cast<const struct secure_dpu_allocate_buffer_req*>(&in_buf[sizeof(struct secure_dpu_req)]);
                  uint64_t req_buffer_len = req_args->buffer_len;
                  LOG(DEBUG) << "Requested buffer length: " << req_buffer_len;

                  struct secure_dpu_resp* rsp = reinterpret_cast<struct secure_dpu_resp*>(out_buf);
                  struct secure_dpu_allocate_buffer_rsp* args = reinterpret_cast<struct secure_dpu_allocate_buffer_rsp*>(&out_buf[sizeof(struct secure_dpu_resp)]);

                  auto result = HandleAllocateBuffer(req_buffer_len, args);
                  if (result == HandleCmdResult::Success) {
                      rsp->status = SECURE_DPU_ERROR_OK;
                  } else {
                      rsp->status = SECURE_DPU_ERROR_FAIL;
                  }

                  rsp->cmd = SECURE_DPU_CMD_ALLOCATE_BUFFER | SECURE_DPU_CMD_RESP_BIT;
                  out_size = sizeof(struct secure_dpu_resp) + sizeof(struct secure_dpu_allocate_buffer_rsp);
                  break;
              }
              case SECURE_DPU_CMD_FREE_BUFFER: {
                  if (in_size != sizeof(struct secure_dpu_req) + sizeof(struct secure_dpu_free_buffer_req)) {
                      return {HandleCmdResult::Fail, "Invalid payload"};
                  }
                  const struct secure_dpu_free_buffer_req* req_args = reinterpret_cast<const struct secure_dpu_free_buffer_req*>(&in_buf[sizeof(struct secure_dpu_req)]);
                  uint64_t req_buffer_ptr = req_args->buffer_phy_addr;
                  uint64_t req_buffer_len = req_args->buffer_len;
                  LOG(DEBUG) << "Requested buffer address: " << req_buffer_ptr;
                  LOG(DEBUG) << "Requested buffer length: " << req_buffer_len;

                  struct secure_dpu_resp* rsp = reinterpret_cast<struct secure_dpu_resp*>(out_buf);
                  rsp->cmd = SECURE_DPU_CMD_FREE_BUFFER | SECURE_DPU_CMD_RESP_BIT;

                  auto result = HandleFreeBuffer(req_buffer_ptr, req_buffer_len);
                  if (result == HandleCmdResult::Success) {
                      rsp->status = SECURE_DPU_ERROR_OK;
                  } else {
                      rsp->status = SECURE_DPU_ERROR_FAIL;
                  }

                  out_size = sizeof(struct secure_dpu_resp);
                  break;
              }
              case SECURE_DPU_CMD_START_SECURE_DISPLAY: {
                  struct secure_dpu_resp* rsp = reinterpret_cast<struct secure_dpu_resp*>(out_buf);
                  rsp->cmd = SECURE_DPU_CMD_START_SECURE_DISPLAY | SECURE_DPU_CMD_RESP_BIT;

                  auto result = HandleStartSecureDisplay();
                  if (result == HandleCmdResult::Success) {
                      rsp->status = SECURE_DPU_ERROR_OK;
                  } else {
                      rsp->status = SECURE_DPU_ERROR_FAIL;
                  }

                  out_size = sizeof(struct secure_dpu_resp);
                  break;
              }
              case SECURE_DPU_CMD_STOP_SECURE_DISPLAY: {
                  struct secure_dpu_resp* rsp = reinterpret_cast<struct secure_dpu_resp*>(out_buf);
                  rsp->cmd = SECURE_DPU_CMD_STOP_SECURE_DISPLAY | SECURE_DPU_CMD_RESP_BIT;

                  auto result = HandleStopSecureDisplay();
                  if (result == HandleCmdResult::Success) {
                      rsp->status = SECURE_DPU_ERROR_OK;
                  } else {
                      rsp->status = SECURE_DPU_ERROR_FAIL;
                  }

                  out_size = sizeof(struct secure_dpu_resp);
                  break;
              }
              default:
                  LOG(ERROR) << "Unknown command: " << (uint32_t)req->cmd;
                  return {HandleCmdResult::Fail, {"Unknown command"}};
        }
        return {HandleCmdResult::Success, {}};
    }


  public:
    static constexpr const size_t maxBufferSize = 64;

    DPUHandler(handleCb cb);
    ~DPUHandler();

    std::tuple<int, std::string> handle(const uint8_t in_buf[], const size_t in_size) {
        std::lock_guard<std::mutex> lock(mutex_);

        uint8_t out_buf[maxBufferSize];
        size_t out_size = 0;

        if (handle_ == kInvalidHandle) {
            return {-1, "Invalied handler"};
        }

        auto [rc, err_msg] = handleCmd(in_buf, in_size, out_buf, out_size);
        switch (rc) {
            case HandleCmdResult::Fail:
                return {-1, err_msg};
            case HandleCmdResult::Success:
                break;
        }

        if (sendMsgCb(out_buf, out_size)) {
            return {-1, "Failed to send back to dpu"};
        }
        return {0, {}};
    }
};

}  // namespace dpu_handler
}  // namespace android
