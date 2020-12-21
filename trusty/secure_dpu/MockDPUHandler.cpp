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
#include "secure_dpu_proto.h"

#include <android-base/logging.h>
#include <string>
#include <memory>

namespace android {
namespace dpu_handler {

DPUHandler::DPUHandler(handleCb cb) : handle_(kInvalidHandle), sendMsgCb(cb) {
    handle_ = 100;
}

DPUHandler::~DPUHandler() {}

HandleCmdResult DPUHandler::HandleAllocateBuffer(const uint64_t req_buffer_len,
                                                 struct secure_dpu_allocate_buffer_rsp* args) {
    args->buffer_phy_addr = 0x12345678;
    args->buffer_len = req_buffer_len;
    return HandleCmdResult::Success;
}

HandleCmdResult DPUHandler::HandleFreeBuffer(const uint64_t req_buffer_ptr,
                                             const uint64_t req_buffer_len) {
    (void)req_buffer_ptr;
    (void)req_buffer_len;
    return HandleCmdResult::Success;
}

HandleCmdResult DPUHandler::HandleStartSecureDisplay() {
    LOG(INFO) << "Started Secure Display.";
    return HandleCmdResult::Success;
}

HandleCmdResult DPUHandler::HandleStopSecureDisplay() {
    LOG(INFO) << "Stopped Secure Display.";
    return HandleCmdResult::Success;
}

}  // namespace dpu_handler
}  // namespace android
