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
#include <secure_dpu/secure_dpu_proto.h>

#include <android-base/logging.h>
#include <string>
#include <memory>

namespace android {
namespace dpu_handler {

DPUHandler::DPUHandler(handleCb cb) : handle_(kInvalidHandle), sendMsgCb(cb) {
    handle_ = 100;
}

DPUHandler::~DPUHandler() {}

std::tuple<HandleCmdResult, std::string> DPUHandler::handleCmd(uint8_t buf[], size_t& size) {
    if (size < sizeof(struct secure_dpu_req)) {
        size = 0;
        return {HandleCmdResult::Fail, "Invalid payload"};
    }
    struct secure_dpu_req* req = reinterpret_cast<secure_dpu_req*>(buf);
    switch (req->cmd) {
    case SECURE_DPU_CMD_ALLOCATE_BUFFER: {
        if (size < sizeof(struct secure_dpu_resp) + sizeof(struct secure_dpu_allocate_buffer_rsp)) {
            LOG(ERROR) << "No enough buffer";
            size = 0;
            break;
        }
        struct secure_dpu_allocate_buffer_req* req_args = reinterpret_cast<struct secure_dpu_allocate_buffer_req*>(&buf[sizeof(struct secure_dpu_req)]);
        uint64_t req_buffer_len = req_args->buffer_len;
        LOG(DEBUG) << "Requested buffer length: " << req_buffer_len;

        struct secure_dpu_resp* rsp = reinterpret_cast<struct secure_dpu_resp*>(buf);
        struct secure_dpu_allocate_buffer_rsp* args = reinterpret_cast<struct secure_dpu_allocate_buffer_rsp*>(&buf[sizeof(struct secure_dpu_resp)]);
        rsp->cmd = SECURE_DPU_CMD_ALLOCATE_BUFFER | SECURE_DPU_CMD_RESP_BIT;
        rsp->status = SECURE_DPU_ERROR_OK;
        args->buffer_phy_addr = 0x12345678;
        args->buffer_len = req_buffer_len;
        size = sizeof(struct secure_dpu_resp) + sizeof(struct secure_dpu_allocate_buffer_rsp);
        break;
    }
    case SECURE_DPU_CMD_FREE_BUFFER: {
        if (size < sizeof(struct secure_dpu_resp)) {
            LOG(ERROR) << "No enough buffer";
            size = 0;
            break;
        }
        struct secure_dpu_free_buffer_req* req_args = reinterpret_cast<struct secure_dpu_free_buffer_req*>(&buf[sizeof(struct secure_dpu_req)]);
        uint64_t req_buffer_ptr = req_args->buffer_phy_addr;
        uint64_t req_buffer_len = req_args->buffer_len;
        LOG(DEBUG) << "Requested buffer address: " << req_buffer_ptr;
        LOG(DEBUG) << "Requested buffer length: " << req_buffer_len;

        struct secure_dpu_resp* rsp = reinterpret_cast<struct secure_dpu_resp*>(buf);
        rsp->cmd = SECURE_DPU_CMD_FREE_BUFFER | SECURE_DPU_CMD_RESP_BIT;
        rsp->status = SECURE_DPU_ERROR_OK;
        size = sizeof(struct secure_dpu_resp);
        break;
    }
    case SECURE_DPU_CMD_START_SECURE_DISPLAY: {
        if (size < sizeof(struct secure_dpu_resp)) {
            LOG(ERROR) << "No enough buffer";
            size = 0;
            break;
        }
        struct secure_dpu_resp* rsp = reinterpret_cast<struct secure_dpu_resp*>(buf);
        rsp->cmd = SECURE_DPU_CMD_START_SECURE_DISPLAY | SECURE_DPU_CMD_RESP_BIT;
        rsp->status = SECURE_DPU_ERROR_OK;
        size = sizeof(struct secure_dpu_resp);
        break;
    }
    case SECURE_DPU_CMD_STOP_SECURE_DISPLAY: {
        if (size < sizeof(struct secure_dpu_resp)) {
            LOG(ERROR) << "No enough buffer";
            size = 0;
            break;
        }
        struct secure_dpu_resp* rsp = reinterpret_cast<struct secure_dpu_resp*>(buf);
        rsp->cmd = SECURE_DPU_CMD_STOP_SECURE_DISPLAY | SECURE_DPU_CMD_RESP_BIT;
        rsp->status = SECURE_DPU_ERROR_OK;
        size = sizeof(struct secure_dpu_resp);
        break;
    }
    default:
        LOG(ERROR) << "Unknown command: " << (uint32_t)req->cmd;
        size = 0;
        return {HandleCmdResult::Fail, {"Unknown command"}};
    }
    return {HandleCmdResult::Success, {}};
}

}  // namespace dpu_handler
}  // namespace android
