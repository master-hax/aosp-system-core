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
#include <crypto/key_store.h>

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

PairingClient::~PairingClient() {
    if (mPairingAuthCtx != nullptr) {
        pairing_auth_delete_ctx(mPairingAuthCtx);
        mPairingAuthCtx = nullptr;
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
    auto keystore_ctx = keystore_get();
    if (keystore_ctx == nullptr) {
        LOG(ERROR) << "Keystore context is null";
        return false;
    }

    switch(dataType) {
        case DataType::PublicKey: {
            LOG(INFO) << "Registering their public key";
            if(!pairing_auth_register_their_key(mPairingAuthCtx,
                                                reinterpret_cast<const uint8_t*>(msg.data()),
                                                msg.size())) {
                LOG(ERROR) << "Failed to register their public key";
                return false;
            }
            // Get the system's PublicKeyHeader and public key from the keystore
            // to build a pairing request.
            PublicKeyHeader public_key_header;
            keystore_public_key_header(keystore_ctx, &public_key_header);
            std::vector<char> public_key(keystore_max_certificate_size(keystore_ctx));
            uint32_t public_key_sz = keystore_system_public_key(keystore_ctx, public_key.data());
            if (public_key_sz == 0) {
                LOG(ERROR) << "Unable to retrieve the system's public certificate.";
                return false;
            }
            public_key.resize(public_key_sz);
            uint32_t pktSize = pairing_auth_request_max_size();
            std::vector<uint8_t> pkt(pktSize);
            if (!pairing_auth_create_request(mPairingAuthCtx,
                                             &public_key_header,
                                             public_key.data(),
                                             pkt.data(),
                                             &pktSize)) {
                LOG(ERROR) << "Unable to create pairing request packet.";
                return false;
            }
            pkt.resize(pktSize);
            if (!mConnection.sendRawMsg(pkt.data(),
                                        pkt.size())) {
                LOG(ERROR) << "Unable to send pairing request packet.";
                return false;
            }
            break;
        }
        case DataType::PairingRequest: {
            LOG(INFO) << "Got device's system public key pairing request";
            PublicKeyHeader header;
            std::vector<char> public_key(keystore_max_certificate_size(mPairingAuthCtx), '\0');
            bool valid = pairing_auth_parse_request(mPairingAuthCtx,
                                                    reinterpret_cast<const uint8_t*>(msg.data()),
                                                    msg.size(),
                                                    &header,
                                                    public_key.data());
            if (!valid) {
                LOG(ERROR) << "Unable to parse the device's pairing request.";
                return false;
            }

            public_key.resize(header.payload);
            valid = keystore_store_public_key(keystore_ctx,
                                              &header,
                                              public_key.data());
            if (!valid) {
                LOG(ERROR) << "Unable to write the device's key into the keystore.";
                return false;
            }
            break;
        }
    }

    return true;
}

// static
bool PairingClient::processMsg(std::string_view msg,
                               DataType dataType,
                               int /* fd */,
                               void* opaque) {
    auto* ptr = reinterpret_cast<PairingClient*>(opaque);
    return ptr->handleMsg(msg, dataType);
}
