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

#include "ProxyHandler.h"
#include <secure_fb_proxy/secure_fb_proxy_proto.h>

#include <android-base/logging.h>
#include <memory>

namespace android {
namespace proxy_handler {

ProxyHandler::ProxyHandler() : handle_(kInvalidHandle) {
    handle_ = 100;
}

ProxyHandler::~ProxyHandler() {}

void ProxyHandler::handleCmd(uint8_t buf[], size_t& size) {
    if (size < sizeof(ProxyRequest)) {
        LOG(ERROR) << "Invalid payload";
        size = 0;
        return;
    }
    ProxyRequest* req = reinterpret_cast<ProxyRequest*>(buf);
    switch (req->cmd) {
    case AllocateFrameBuffer: {
        if (size < sizeof(AllocateFrameBufferResponse)) {
            LOG(ERROR) << "No enough buffer";
            size = 0;
            break;
        }
        AllocateFrameBufferResponse* rsp = reinterpret_cast<AllocateFrameBufferResponse*>(buf);
        rsp->result = ProxyCommandResult::Success;
        rsp->phy_addr = 0x12345678;
        rsp->size = 0x10000000;
        size = sizeof(AllocateFrameBufferResponse);
        break;
    }
    default:
        LOG(ERROR) << "Unknown command: " << (uint32_t)req->cmd;
        size = 0;
        break;
    }
}

}  // namespace proxy_handler
}  // namespace android
