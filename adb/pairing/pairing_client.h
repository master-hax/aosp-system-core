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

#include "pairing_connection.h"

#include "pairing/pairing_auth.h"

#include <functional>
#include <string>

class PairingClient {
public:
    using ResultCallback = std::function<void (bool /*success*/)>;
    PairingClient(const std::string& password, ResultCallback callback);
    virtual ~PairingClient();

    bool connect(const std::string& address,
                 int port,
                 std::string* response);

    bool handleMsg(std::string_view msg,
                   PairingConnection::DataType dataType);

    // Message handler for PairingConnection.
    static bool processMsg(std::string_view msg,
                           PairingConnection::DataType dataType,
                           int fd,
                           void* opaque);
private:
    ResultCallback mCallback;
    PairingConnection mConnection;
    PairingAuthCtx mPairingAuthCtx = nullptr;
};

