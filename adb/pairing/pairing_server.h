/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
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

#include "adb_unique_fd.h"
#include "pairing_connection.h"

#include <memory>
#include <string>
#include <unordered_map>

class PairingServer {
public:
    using ResultCallback = std::function<void (bool /*success*/)>;
    PairingServer(const uint8_t* ourPublicKey, uint64_t sz);

    // Start listening for connections, if |port| is set to zero the server
    // will choose a port at random.
    bool listen(std::string* response, int port = 0);
    int getPort() const;

private:
    static void staticOnFdEvent(int fd, unsigned ev, void* data);
    void onFdEvent(int fd, unsigned ev);
    void onConnectionCallback(bool success);

    static bool processMsg(std::string_view msg,
                           PairingConnection::DataType dataType,
                           void* opaque);
    bool handleMsg(std::string_view msg,
                   PairingConnection::DataType dataType);

    using ConnectionPtr = std::unique_ptr<PairingConnection>;

    fdevent* mFdEvent = nullptr;
    std::unordered_map<int, ConnectionPtr> mConnections;
    std::vector<uint8_t> mOurKey;
};

