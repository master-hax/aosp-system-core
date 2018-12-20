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

#include <openssl/curve25519.h>

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "adb_unique_fd.h"
#include "crypto/aes_128_gcm.h"
#include "crypto/key_type.h"
#include "fdevent.h"

class PairingConnection {
public:
    using ResultCallback = std::function<void (bool success)>;
    static constexpr int kSpake2Port = 5013;
    static constexpr size_t kMaxAuthMsgSize = 32;
    enum class Mode {
        Client,
        Server,
    };
    enum class State {
        New,
        Connected,
        SendingPublicKey,
        Authenticated,
        Completed,
        Terminated,
    };

    explicit PairingConnection(ResultCallback callback);
    ~PairingConnection();
    bool start(Mode mode, int fd, const std::string& password);

    State state() const { return state_; }

    bool receive();

    int readAuthentication(uint8_t (&authMsg)[kMaxAuthMsgSize]);

    bool establishEncryption(const uint8_t* authMsg, size_t size);

private:
    bool sendAuthentication(const std::string& password);
    bool exchangeKeys(std::string* response);
    // Create the initial message to establish a secure channel for
    // communicating pairing data.
    bool createPairingMessage(const std::string& password);

    bool sendRawMsg(const uint8_t* data, uint32_t size);
    bool sendSecureMsg(const uint8_t* data, uint32_t size);

    bool authenticate();
    bool sendPublicKey();
    int readPublicKey();

    void terminate();

    static void staticOnFdEvent(int fd, unsigned ev, void* data);
    void onFdEvent(int fd, unsigned ev);

    ResultCallback callback_;
    Mode mode_;
    bssl::UniquePtr<SPAKE2_CTX> context_;
    std::vector<uint8_t> pairing_message_;
    std::vector<uint8_t> rx_buffer_;
    fdevent* fdevent_ = nullptr;
    State state_ = State::New;
    crypto::Aes128Gcm cipher_;
    KeyType key_type_ = KeyType::EllipticCurve;
};

