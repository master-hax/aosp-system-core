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

#include "pairing_connection.h"

#include <android-base/logging.h>

#include <mutex>

#include "adb_io.h"
#include "adb_wifi.h"
#include "fdevent/fdevent.h"
#include "sysdeps.h"

static constexpr size_t kRxSize = 1024;
static constexpr size_t kMaxRxSize = 32768;
// These values are intentionally larger than what the actual values will be,
// in the case where adding later pairing protocols sends larger pairing
// requests.
static constexpr size_t kMaxKeySize = 1024;
static constexpr uint32_t kMaxPairingRequestSize = 8192;

PairingConnection::PairingConnection(ResultCallback callback,
                                     DataCallback dataCb,
                                     void* opaque) :
    mCallback(callback),
    mDataCallback(dataCb),
    mOpaque(opaque) {
    // Reserve some space up front to avoid allocations in the receive path for
    // the common use cases.
    mRxBuffer.reserve(4 * kRxSize);
}

PairingConnection::~PairingConnection() {
    LOG(ERROR) << "PairingConnection closing";
    // TODO: do we need to destroy the fdevent here?
}

bool PairingConnection::start(PairingRole role, int fd) {
    LOG(ERROR) << "PairingConnection::start checking main thread";
    check_main_thread();
    LOG(ERROR) << "PairingConnection::start on main thread with fd " << fd;

    mRole = role;
    // Server is waiting for the PublicKeyHeader
    switch (mRole) {
        case PairingRole::Client:
            mState = State::ExchangingKeys;
            break;
        case PairingRole::Server:
            mState = State::ExchangingHeaders;
            break;
    }

    mFdEvent = fdevent_create(fd, &PairingConnection::staticOnFdEvent, this);
    if (mFdEvent == nullptr) {
        LOG(ERROR) << "Unable to create fdevent for PairingConnection";
        terminate();
        return false;
    }
    fdevent_set(mFdEvent, FDE_READ);

    return true;
}

bool PairingConnection::receive() {
    size_t offset = mRxBuffer.size();
    mRxBuffer.resize(offset + kRxSize);
    if (mRxBuffer.size() > kMaxRxSize) {
        // The receive buffer has exceeded the maximum reasonable size, whoever
        // we're talking to is not playing nicely, close this connection.
        terminate();
        return false;
    }
    int bytes = adb_read(mFdEvent->fd,
                         &mRxBuffer[offset],
                         mRxBuffer.size() - offset);
    if (bytes <= 0) {
        mRxBuffer.resize(offset);
        terminate();
        return false;
    }
    PLOG(ERROR) << "received " << bytes << " bytes of data";
    mRxBuffer.resize(offset + static_cast<size_t>(bytes));
    return true;
}

bool PairingConnection::tryReadPublicKey(std::vector<uint8_t>& theirKey) {
    LOG(ERROR) << "Attempting to read PublicKey";
    uint8_t key[kMaxRxSize];
    int bytes = readPublicKey(key);
    LOG(INFO) << "Got " << bytes << " bytes";
    if (bytes < 0) {
        // Something went really wrong, connection closed
        terminate();
        return false;
    } else if (bytes == 0) {
        // Not enough data yet, wait
        return false;
    }

    theirKey.assign(key, key + bytes);
    return true;
}

int PairingConnection::readPublicKey(uint8_t* authMsg) {
    if (mRxBuffer.size() < sizeof(uint32_t)) {
        return 0;
    }
    uint32_t length = ntohl(*reinterpret_cast<uint32_t*>(mRxBuffer.data()));
    if (length > kMaxKeySize) {
        // The size is way too big for a public key. Bad data.
        LOG(ERROR) << "Received public key that has unusual length (" << length << "). Aborting.";
        terminate();
        return -1;
    }
    if (mRxBuffer.size() < length + sizeof(length)) {
        // Not enough data yet, keep receiving
        return 0;
    }

    memcpy(authMsg, mRxBuffer.data() + sizeof(length), length);
    mRxBuffer.erase(mRxBuffer.begin(),
                     mRxBuffer.begin() + sizeof(length) + length);
    return length;
}

bool PairingConnection::tryReadPairingRequest(std::vector<uint8_t>& header) {
    LOG(ERROR) << "Attempting to read PublicKeyHeader";
    std::vector<uint8_t> buf(kMaxPairingRequestSize);
    int bytes = readPairingRequest(buf.data());
    LOG(INFO) << "Got " << bytes << " bytes";
    if (bytes < 0) {
        // Something went really wrong, connection closed
        terminate();
        return false;
    } else if (bytes == 0) {
        // Not enough data yet, wait
        return false;
    }

    header.assign(buf.data(), buf.data() + bytes);
    return true;
}

int PairingConnection::readPairingRequest(uint8_t* header) {
    if (mRxBuffer.size() < sizeof(uint32_t)) {
        return 0;
    }
    uint32_t length = ntohl(*reinterpret_cast<uint32_t*>(mRxBuffer.data()));
    uint32_t maxSize = kMaxPairingRequestSize;
    if (length > maxSize) {
        LOG(ERROR) << "pairing request size bigger than expected (theirs=" << length
                   << "max=" << maxSize << "). Aborting for safety.";
        terminate();
        return -1;
    }
    if (mRxBuffer.size() < length + sizeof(length)) {
        // Not enough data yet, keep receiving
        return 0;
    }

    memcpy(header, mRxBuffer.data() + sizeof(length), length);
    mRxBuffer.erase(mRxBuffer.begin(),
                     mRxBuffer.begin() + sizeof(length) + length);
    return length;
}

bool PairingConnection::sendRawMsg(const uint8_t* data, uint32_t size) {
    uint32_t networkSize = htonl(size);
    if (!WriteFdExactly(mFdEvent->fd, &networkSize, sizeof(networkSize))) {
        return false;
    }
    if (!WriteFdExactly(mFdEvent->fd, data, size)) {
        return false;
    }
    return true;
}

void PairingConnection::terminate() {
    LOG(ERROR) << "PairingConnection::terminate called";
    check_main_thread();
    LOG(ERROR) << "PairingConnection::terminate on main thread";

    mState = State::Terminated;
    mCallback(false);
}

void PairingConnection::staticOnFdEvent(int fd, unsigned ev, void* data) {
    if (ev & FDE_ERROR) {
        return;
    }
    auto connection = reinterpret_cast<PairingConnection*>(data);
    connection->onFdEvent(fd, ev);
}

void PairingConnection::onFdEvent(int fd, unsigned ev) {
    PLOG(ERROR) << "PairingConnection::onServerFdEvent called with ev: 0x" << std::hex << ev;
    check_main_thread();
    PLOG(ERROR) << "PairingConnection::onServerFdEvent on main thread";

    std::vector<uint8_t> buf;

    if ((ev & FDE_READ) == 0 || fd != mFdEvent->fd.get()) {
        return;
    }

    if (!receive()) {
        return;
    }

    while (true) {
        switch (mState) {
            case State::ExchangingKeys:
                LOG(INFO) << "Waiting for public key";
                if (tryReadPublicKey(buf)) {
                    LOG(INFO) << "Got public key";
                    mState = State::ExchangingHeaders;
                    mDataCallback(std::string_view(reinterpret_cast<const char*>(buf.data()),
                                                   buf.size()),
                                  DataType::PublicKey,
                                  mOpaque);
                    continue;
                }
                break;
            case State::ExchangingHeaders:
                if (tryReadPairingRequest(buf)) {
                    if (mDataCallback(std::string_view(reinterpret_cast<const char*>(buf.data()),
                                                   buf.size()),
                                  DataType::PairingRequest,
                                  mOpaque)) {
                        mState = State::Completed;
                    } else {
                        terminate();
                        return;
                    }
                    continue;
                }
                break;
            case State::Completed:
                // For the client, store the public key here in a keystore. The
                // server already handles this.
                mCallback(true);
                break;
            default:
                // Unexpected state, we shouldn't receive anything here
                LOG(ERROR) << "received data in unexpected state "
                           << static_cast<int>(mState);
                terminate();
        }
        // At this point there's no more data to process
        break;
    }
}

// TODO: Move this somewhere else.
//bool PairingConnection::sendPublicKeyHeader(std::string_view header) {
//    std::vector<uint8_t> msg(key->size() + sizeof(PublicKeyHeader));
//
//    auto& header = *reinterpret_cast<PublicKeyHeader*>(msg.data());
//    uint8_t* keyLocation = msg.data() + sizeof(PublicKeyHeader);
//    header.version = kCurrentKeyHeaderVersion;
//    header.type = static_cast<uint8_t>(key->type());;
//    header.bits = htonl(key->bits());
//    header.payload = htonl(key->size());
//    strncpy(header.name, get_device_name().c_str(), sizeof(header.name));
//    header.name[sizeof(header.name) - 1] = '\0';
//    strncpy(header.id, get_unique_device_id().c_str(), sizeof(header.id));
//    header.id[sizeof(header.id) - 1] = '\0';
//
//    memcpy(keyLocation, key->c_str(), key->size());
//
//    if (!sendSecureMsg(msg.data(), msg.size())) {
//        LOG(ERROR) << "Unable send public key: failed to send secure message";
//        terminate();
//        return false;
//    }
//    return true;
//}

// TODO: move this somewhere else.
// Safely extract the string from an array of data. If |data| does not contain
// a terminating null then the resulting string will be created from all the
// contents of |data| and a terminating null will be appended. If there is a
// terminating null in |data| the resulting string will be terminated at that
// the first null terminator.
//static std::string getSafeString(const char* data, size_t length) {
//    std::string result;
//    if (::memchr(data, '\0', length) != nullptr) {
//        result = data;
//    } else {
//        result.assign(data, length);
//    }
//    return result;
//}

// TODO: move this somewhere else.
//int PairingConnection::readPublicKeyHeader() {
//    LOG(ERROR) << "Attempting to read public key";
//    int requiredSize = cipher_.decryptedSize(mRxBuffer.data(),
//                                             mRxBuffer.size());
//    if (requiredSize == 0) {
//        return 0;
//    } else if (requiredSize < 0) {
//        terminate();
//        return -1;
//    }
//    std::vector<uint8_t> decrypted(requiredSize);
//    size_t decryptedSize = decrypted.size();
//    int bytes = cipher_.decrypt(mRxBuffer.data(), mRxBuffer.size(),
//                                decrypted.data(), &decryptedSize);
//    if (bytes == 0) {
//        return 0;
//    } else if (bytes < 0) {
//        terminate();
//        return -1;
//    }
//
//    mRxBuffer.erase(mRxBuffer.begin(),
//                     mRxBuffer.begin() + static_cast<size_t>(bytes));
//    if (decryptedSize == 0) {
//        return 0;
//    }
//    decrypted.resize(decryptedSize);
//
//    auto header = reinterpret_cast<const PublicKeyHeader*>(decrypted.data());
//    const uint8_t* keyLocation = decrypted.data() + sizeof(PublicKeyHeader);
//
//    if (header->version > kMaxSupportedKeyHeaderVersion ||
//        header->version < kMinSupportedKeyHeaderVersion) {
//        LOG(ERROR) << "Unsupported key header version " << header->version;
//        terminate();
//        return -1;
//    }
//    KeyType type;
//    if (!getKeyTypeFromValue(header->type, &type)) {
//        LOG(ERROR) << "Received unknown key type " << header->type;
//        terminate();
//        return -1;
//    }
//
//    std::string id = getSafeString(header->id, sizeof(header->id));
//    std::string name = getSafeString(header->name, sizeof(header->name));
//
//    uint32_t keyLength = ntohl(header->payload);
//    std::string key = getSafeString(reinterpret_cast<const char*>(keyLocation),
//                                    keyLength);
//
//    KeyStore* keyStore = getKeyStore();
//    if (!keyStore) {
//        terminate();
//        return -1;
//    }
//
//    keyStore->storePublicKey(id, name, type, key);
//
//    return bytes;
//}
