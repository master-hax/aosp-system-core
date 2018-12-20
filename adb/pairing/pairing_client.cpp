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

#include "pairing_client.h"

#include <android-base/parsenetaddress.h>

#include "sysdeps.h"

using android::base::ParseNetAddress;

PairingClient::PairingClient(const std::string& password,
                             ResultCallback callback) 
    : password_(password), callback_(callback), connection_(callback) {
}

bool PairingClient::connect(const std::string& address,
                            int port,
                            std::string* response) {
    std::string host;
    if (!ParseNetAddress(address, &host, &port, nullptr, response)) {
        *response = "invalid network address";
        return false;
    }

    std::string error;
    int fd = network_connect(host, port, SOCK_STREAM, 0, &error);
    if (fd == -1) {
        *response = "unable to connect to address: " + error;
        return false;
    }
    disable_tcp_nagle(fd);

    if (!connection_.start(PairingConnection::Mode::Client, fd, password_)) {
        *response = "internal initialization failure";
        return false;
    }
    return true;
}

