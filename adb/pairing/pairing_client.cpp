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

#include <android-base/logging.h>
#include <android-base/parsenetaddress.h>

#include "sysdeps.h"

using android::base::ParseNetAddress;
using DataType = PairingConnection::DataType;

PairingClient::PairingClient(const std::string& password,
                             ResultCallback callback) :
    mCallback(callback),
    mConnection(callback, processMsg, this) {
    mPairingAuthCtx = pairing_auth_new_ctx(PairingRole::Client,
                                           reinterpret_cast<const uint8_t*>(password.data()),
                                           password.size());
    if (mPairingAuthCtx == nullptr) {
        LOG(ERROR) << "Unable to create a pairing auth context.";
        return;
    }
}

bool PairingClient::connect(const std::string& address,
                            int port,
                            std::string* response) {
    if (mPairingAuthCtx == nullptr) {
        LOG(ERROR) << "Pairing auth context is null";
        return false;
    }

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

    if (!mConnection.start(PairingRole::Client, fd)) {
        *response = "internal initialization failure";
        return false;
    }

    return true;
}

bool PairingClient::handleMsg(std::string_view msg,
                              DataType dataType) {
    switch(dataType) {
        case DataType::PublicKey: {
            LOG(INFO) << "Registering their public key";
            if(!pairing_auth_register_their_key(mPairingAuthCtx,
                                                reinterpret_cast<const uint8_t*>(msg.data()),
                                                msg.size())) {
                LOG(ERROR) << "Failed to register their public key";
                return false;
            }
            uint32_t pktSize = pairing_auth_request_max_size(mPairingAuthCtx);
            std::vector<uint8_t> header(pktSize);
            if (!pairing_auth_create_request(mPairingAuthCtx,
                                             header.data(),
                                             &pktSize)) {
                LOG(ERROR) << "Unable to create header packet";
                return false;
            }
            header.resize(pktSize);
            if (!mConnection.sendRawMsg(header.data(),
                                         header.size())) {
                LOG(ERROR) << "Unable to send header packet";
            }
            break;
        }
        default:
            LOG(ERROR) << "unhandled DataType";
            break;
    }

    return true;
}

// static
bool PairingClient::processMsg(std::string_view msg,
                               DataType dataType,
                               void* opaque) {
    auto* ptr = reinterpret_cast<PairingClient*>(opaque);
    return ptr->handleMsg(msg, dataType);
}
