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

#include "DPUHandler.h"
#include "SecureDpu.h"

#include <android-base/logging.h>
#include <string>
#include <memory>

namespace android {
namespace trusty {
namespace secure_dpu {

DPUHandler::DPUHandler(handleCb cb) : handle_(kInvalidHandle), sendMsgCb(cb) {
    handle_ = 100;
}

DPUHandler::~DPUHandler() {}

android::base::Result<void> DPUHandler::HandleAllocateBuffer(const uint64_t req_buffer_len,
                                                 struct secure_dpu_allocate_buffer_rsp* args) {
    args->buffer_phy_addr = 0x12345678;
    args->buffer_len = req_buffer_len;
    return {};
}

android::base::Result<void> DPUHandler::HandleFreeBuffer(const uint64_t req_buffer_ptr,
                                             const uint64_t req_buffer_len) {
    (void)req_buffer_ptr;
    (void)req_buffer_len;
    return {};
}

android::base::Result<void> DPUHandler::HandleStartSecureDisplay() {
    LOG(INFO) << "Started Secure Display.";
    return {};
}

android::base::Result<void> DPUHandler::HandleStopSecureDisplay() {
    LOG(INFO) << "Stopped Secure Display.";
    return {};
}

android::base::Result<void> DPUHandler::HandleCmd(const uint8_t in_buf[],
                                                  const size_t in_size,
                                                  uint8_t out_buf[],
                                                  size_t &out_size) {
    if (in_size < sizeof(struct secure_dpu_req)) {
        return base::Error() << "Invalid payload";
    }
    const struct secure_dpu_req* req = reinterpret_cast<const struct secure_dpu_req*>(in_buf);
    switch (req->cmd) {
        case SECURE_DPU_CMD_ALLOCATE_BUFFER: {
            if (in_size != sizeof(struct secure_dpu_req) +
                           sizeof(struct secure_dpu_allocate_buffer_req)) {
                return base::Error() << "Invalid payload";
            }
            const struct secure_dpu_allocate_buffer_req* req_args =
                reinterpret_cast<const struct secure_dpu_allocate_buffer_req*>
                (&in_buf[sizeof(struct secure_dpu_req)]);
            uint64_t req_buffer_len = req_args->buffer_len;
            LOG(DEBUG) << "Requested buffer length: " << req_buffer_len;

            struct secure_dpu_resp* rsp = reinterpret_cast<struct secure_dpu_resp*>(out_buf);
            struct secure_dpu_allocate_buffer_rsp* args =
                reinterpret_cast<struct secure_dpu_allocate_buffer_rsp*>
                (&out_buf[sizeof(struct secure_dpu_resp)]);

            auto result = HandleAllocateBuffer(req_buffer_len, args);
            if (result.ok()) {
                rsp->status = SECURE_DPU_ERROR_OK;
            } else {
                rsp->status = SECURE_DPU_ERROR_FAIL;
            }

            rsp->cmd = SECURE_DPU_CMD_ALLOCATE_BUFFER | SECURE_DPU_CMD_RESP_BIT;
            out_size = sizeof(struct secure_dpu_resp) +
                       sizeof(struct secure_dpu_allocate_buffer_rsp);
            break;
        }
        case SECURE_DPU_CMD_FREE_BUFFER: {
            if (in_size != sizeof(struct secure_dpu_req) +
                           sizeof(struct secure_dpu_free_buffer_req)) {
                return base::Error() << "Invalid payload";
            }
            const struct secure_dpu_free_buffer_req* req_args =
                reinterpret_cast<const struct secure_dpu_free_buffer_req*>
                (&in_buf[sizeof(struct secure_dpu_req)]);
            uint64_t req_buffer_ptr = req_args->buffer_phy_addr;
            uint64_t req_buffer_len = req_args->buffer_len;
            LOG(DEBUG) << "Requested buffer address: " << req_buffer_ptr;
            LOG(DEBUG) << "Requested buffer length: " << req_buffer_len;

            struct secure_dpu_resp* rsp = reinterpret_cast<struct secure_dpu_resp*>(out_buf);
            rsp->cmd = SECURE_DPU_CMD_FREE_BUFFER | SECURE_DPU_CMD_RESP_BIT;

            auto result = HandleFreeBuffer(req_buffer_ptr, req_buffer_len);
            if (result.ok()) {
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
            if (result.ok()) {
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
            if (result.ok()) {
                rsp->status = SECURE_DPU_ERROR_OK;
            } else {
                rsp->status = SECURE_DPU_ERROR_FAIL;
            }

            out_size = sizeof(struct secure_dpu_resp);
            break;
        }
        default:
            LOG(ERROR) << "Unknown command: " << (uint32_t)req->cmd;
            return base::Error() << "Unknown command";
    }
    return {};
}


}  // namespace secure_dpu
}  // namespace trusty
}  // namespace android
