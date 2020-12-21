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
    if (size < sizeof(DPURequest)) {
        size = 0;
        return {HandleCmdResult::Fail, "Invalid payload"};
    }
    DPURequest* req = reinterpret_cast<DPURequest*>(buf);
    switch (req->cmd) {
    case AllocateFrameBuffer: {
        if (size < sizeof(AllocateFrameBufferResponse)) {
            LOG(ERROR) << "No enough buffer";
            size = 0;
            break;
        }
        AllocateFrameBufferResponse* rsp = reinterpret_cast<AllocateFrameBufferResponse*>(buf);
        rsp->result = DPUCommandResult::Success;
        rsp->phy_addr = 0x12345678;
        rsp->size = 0x10000000;
        size = sizeof(AllocateFrameBufferResponse);
        break;
    }
    case Abort: {
        size = 0;
        return {HandleCmdResult::Abort, {"Abort command"}};
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
