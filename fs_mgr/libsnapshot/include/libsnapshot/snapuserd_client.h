// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace android {
namespace snapshot {

static constexpr uint32_t PACKET_SIZE = 512;
static constexpr uint32_t PORT_NUM = 65123;
static constexpr uint32_t MAX_CONNECT_RETRY_COUNT = 10;

class SnapuserdClient {
  private:
    int sockfd_ = 0;
    struct sockaddr_in server_;

    int ConnectTo(const std::string& address, int port);
    int Sendmsg(const char* msg, size_t size);
    std::string Receivemsg();

    void Parsemsg(std::string const& msg, const char delim, std::vector<std::string>& out) {
        std::stringstream ss(msg);
        std::string s;

        while (std::getline(ss, s, delim)) {
            out.push_back(s);
        }
    }

  public:
    ~SnapuserdClient() { close(sockfd_); }

    int StartSnapuserd();
    int StopSnapuserd();
    int RestartSnapuserd();
    int InitializeSnapuserd(std::string cow_device, std::string backing_device);
};

}  // namespace snapshot
}  // namespace android
