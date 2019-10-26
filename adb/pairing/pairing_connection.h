/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "adb_unique_fd.h"
#include "fdevent/fdevent.h"
#include "pairing/pairing_auth.h"

class PairingConnection {
public:
    using ResultCallback = std::function<void (bool success)>;
    enum class State {
        New,
        ExchangingKeys,
        ExchangingHeaders,
        Completed,
        Terminated,
    };

    enum class DataType {
        PublicKey,
        PairingRequest,
    };
    using DataCallback = std::function<bool(std::string_view,
                                            DataType,
                                            int,
                                            void*)>;

    explicit PairingConnection(ResultCallback callback,
                               DataCallback dataCb,
                               void* opaque);
    ~PairingConnection();

    // Starts the connection between the client and server. All incoming data
    // will be forwarded to |cb| for further processing. Exchanges |publicKey|
    // with the other party.
    bool start(PairingRole role, int fd);
    // Sends |data| to the server/client.
    bool sendRawMsg(const uint8_t* data, uint32_t size);

    State state() const { return mState; }

    bool receive();



private:

    // Read the incoming public key from the client/server. If return is 0,
    // we didn't get enough bytes and will need to try and read again. If -1,
    // failed. Otherwise, the return is the number of bytes in the |authMsg|.
    int readPublicKey(uint8_t* authMsg);
    // Wrapper to retry readPublicKey until we get enough bytes. If return true,
    // then |theirKey| will have the contents of their key.
    bool tryReadPublicKey(std::vector<uint8_t>& theirKey);

    // Read the incoming pairing request from the client/server. If return is 0,
    // we didn't get enough bytes and will need to try and read again. If -1,
    // failed. Otherwise, the return is the number of bytes in the |header|.
    int readPairingRequest(uint8_t* pkt);
    // Wrapper to retry readPairingRequest until we get enough bytes. If return true,
    // then |pkt| will have the contents of their pairing request.
    bool tryReadPairingRequest(std::vector<uint8_t>& pkt);

    void terminate();

    static void staticOnFdEvent(int fd, unsigned ev, void* data);
    void onFdEvent(int fd, unsigned ev);

    ResultCallback mCallback;
    DataCallback mDataCallback;
    ResultCallback mCompletionCb;
    void* mOpaque;
    PairingRole mRole;
    std::vector<uint8_t> mRxBuffer;
    fdevent* mFdEvent = nullptr;
    State mState = State::New;
//    KeyType key_type_ = KeyType::EllipticCurve;
};

