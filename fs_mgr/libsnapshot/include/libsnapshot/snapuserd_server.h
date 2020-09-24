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

#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include <errno.h>
#include <cstdio>
#include <cstring>
#include <functional>
#include <future>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include <cutils/sockets.h>

namespace android {
namespace snapshot {

static constexpr uint32_t MAX_PACKET_SIZE = 512;

enum class DaemonOperations {
    START,
    QUERY,
    TERMINATING,
    STOP,
    INVALID,
};

class Client {
  private:
    std::thread* threadHandler_;

  public:
    Client() { threadHandler_ = nullptr; }

    ~Client() {
        if (threadHandler_ != nullptr) {
            delete threadHandler_;
            threadHandler_ = nullptr;
        }
    }

    void SetThreadHandler(std::function<void(void)> func) {
        threadHandler_ = new std::thread(func);
    }

    std::thread* GetThreadHandler() { return threadHandler_; }
};

class Stoppable {
    std::promise<void> exitSignal;
    std::future<void> futureObj;

  public:
    Stoppable() : futureObj(exitSignal.get_future()) {}

    virtual ~Stoppable() {}

    virtual void ThreadStart(std::string cow_device, std::string backing_device) = 0;

    bool StopRequested() {
        // checks if value in future object is available
        if (futureObj.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout)
            return false;
        return true;
    }
    // Request the thread to stop by setting value in promise object
    void StopThreads() { exitSignal.set_value(); }
};

class SnapuserdServer : public Stoppable {
  private:
    int sockfd_;
    bool terminating_;
    std::vector<std::unique_ptr<Client>> clients_vec_;
    void ThreadStart(std::string cow_device, std::string backing_device) override;
    void ShutdownThreads();

    DaemonOperations Resolveop(std::string& input) {
        if (input == "start") return DaemonOperations::START;
        if (input == "stop") return DaemonOperations::STOP;
        if (input == "terminate-request") return DaemonOperations::TERMINATING;
        if (input == "query") return DaemonOperations::QUERY;

        return DaemonOperations::INVALID;
    }

    void SetTerminating() { terminating_ = true; }

    bool IsTerminating() { return terminating_; }

    std::string GetDaemonStatus() {
        std::string msg = "";

        if (IsTerminating())
            msg = "passive";
        else
            msg = "active";

        return msg;
    }

    void Parsemsg(std::string const& msg, const char delim, std::vector<std::string>& out) {
        std::stringstream ss(msg);
        std::string s;

        while (std::getline(ss, s, delim)) {
            out.push_back(s);
        }
    }

  public:
    ~SnapuserdServer() {
        clients_vec_.clear();
        close(sockfd_);
    }

    SnapuserdServer() {
        sockfd_ = -1;
        terminating_ = false;
    }

    int Start(std::string socketname);
    int AcceptClient();
    int Receivemsg(int fd);
    int Sendmsg(int fd, char* msg, size_t len);
    std::string Recvmsg(int fd, int* ret);
};

}  // namespace snapshot
}  // namespace android
