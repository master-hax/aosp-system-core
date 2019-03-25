/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <poll.h>

#include <set>

#include "nativezygote.h"
#include "result.h"

namespace android {
namespace init {

class NativeZygoteServer {
  public:
    explicit NativeZygoteServer(const char* socket_name);

    void MainLoop();

  private:
    void HandleRequest();
    void HandleConnection();

    bool ReadRequest();
    void CloseAllSockets();
    void CloseDataSocket();
    std::set<int> GetFileDescriptors();

    std::set<int> CreateAndPublishDescriptors();
    void SetProcessAttributesAndCaps();
    std::vector<char*> ExpandArgsAndSetCmdline();
    void Specialize();

    int ctrl_sock_;
    int data_sock_;
    NativeZygoteRequest req_;
    pollfd poll_fds_[2];
    int nfds_;
};

}  // namespace init
}  // namespace android
