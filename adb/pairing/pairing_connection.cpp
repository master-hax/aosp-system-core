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

#include "pairing_connection.h"

#include <android-base/logging.h>

#include "adb_io.h"
#include "crypto/identifiers.h"
#include "crypto/key_store.h"
#include "crypto/key_type.h"
#include "fdevent.h"
#include "sysdeps.h"

static constexpr spake2_role_t kClientRole = spake2_role_alice;
static constexpr spake2_role_t kServerRole = spake2_role_bob;

static const uint8_t kClientName[] = "adb pair client";
static const uint8_t kServerName[] = "adb pair server";

static constexpr size_t kRxSize = 1024;
static constexpr size_t kMaxRxSize = 32768;

static constexpr uint8_t kCurrentKeyHeaderVersion = 1;
static constexpr uint8_t kMinSupportedKeyHeaderVersion = 1;
static constexpr uint8_t kMaxSupportedKeyHeaderVersion = 1;

struct PublicKeyHeader {
    uint8_t version;
    uint8_t type;
    uint32_t bits;
    uint32_t payload;
    char name[kPublicKeyNameLength];
    char id[kPublicKeyIdLength];
} __attribute__((packed));

PairingConnection::PairingConnection(ResultCallback callback)
    : callback_(callback) {
    // Reserve some space up front to avoid allocations in the recieve path for
    // the common use cases.
    rx_buffer_.reserve(4 * kRxSize);
}

PairingConnection::~PairingConnection() {
    LOG(ERROR) << "PairingConnection closing";
}

bool PairingConnection::start(Mode mode, int fd, const std::string& password) {
    LOG(ERROR) << "PairingConnection::start checking main thread";
    check_main_thread();
    LOG(ERROR) << "PairingConnection::start on main thread with fd " << fd;

    mode_ = mode;

    if (context_) {
        // Already initialized
        return false;
    }

    fdevent_ = fdevent_create(fd, &PairingConnection::staticOnFdEvent, this);
    if (fdevent_ == nullptr) {
        return false;
    }
    fdevent_set(fdevent_, FDE_READ);

    spake2_role_t role;
    const uint8_t* myName = nullptr;
    const uint8_t* theirName = nullptr;
    size_t myLen = 0, theirLen = 0;

    switch (mode) {
        case Mode::Client:
            role = kClientRole;
            myName = kClientName; myLen = sizeof(kClientName);
            theirName = kServerName; theirLen = sizeof(kServerName);
            break;
        case Mode::Server:
            role = kServerRole;
            myName = kServerName; myLen = sizeof(kServerName);
            theirName = kClientName; theirLen = sizeof(kClientName);
            break;
        // No default statement should cause compiler error if enum changes
    }
    context_.reset(SPAKE2_CTX_new(role, myName, myLen, theirName, theirLen));
    if (!context_) {
        return false;
    }
    state_ = State::Connected;

    sendAuthentication(password);

    return true;
}

bool PairingConnection::receive() {
    size_t offset = rx_buffer_.size();
    rx_buffer_.resize(offset + kRxSize);
    if (rx_buffer_.size() > kMaxRxSize) {
        // The receive buffer has exceeded the maximum reasonable size, whoever
        // we're talking to is not playing nicely, close this connection.
        terminate();
        return false;
    }
    int bytes = adb_read(fdevent_->fd,
                         &rx_buffer_[offset],
                         rx_buffer_.size() - offset);
    if (bytes <= 0) {
        rx_buffer_.resize(offset);
        terminate();
        return false;
    }
    LOG(ERROR) << "received " << bytes << " of data";
    rx_buffer_.resize(offset + static_cast<size_t>(bytes));
    return true;
}
bool PairingConnection::sendAuthentication(const std::string& password) {
    if (!createPairingMessage(password)) {
        return false;
    }

    if (!sendRawMsg(pairing_message_.data(), pairing_message_.size())) {
        return false;
    }

    return true;
}

int PairingConnection::readAuthentication(uint8_t (&msg)[kMaxAuthMsgSize]) {
    if (rx_buffer_.size() < sizeof(uint32_t)) {
        return 0;
    }
    uint32_t length = ntohl(*reinterpret_cast<uint32_t*>(rx_buffer_.data()));
    if (rx_buffer_.size() < length + sizeof(length)) {
        // Not enough data yet, keep receiving
        return 0;
    }
    if (length > sizeof(msg)) {
        terminate();
        return -1;
    }

    memcpy(msg, rx_buffer_.data() + sizeof(length), length);
    rx_buffer_.erase(rx_buffer_.begin(),
                     rx_buffer_.begin() + sizeof(length) + length);
    return length;
}

bool PairingConnection::exchangeKeys(std::string* response) {
    return true;
}

bool PairingConnection::createPairingMessage(const std::string& password) {
    size_t size = 0;
    auto pwd = reinterpret_cast<const uint8_t*>(password.c_str());
    pairing_message_.resize(SPAKE2_MAX_MSG_SIZE);
    int status = SPAKE2_generate_msg(context_.get(), pairing_message_.data(),
                                     &size, pairing_message_.size(),
                                     pwd, password.size());
    if (status != 1) {
        // Failure
        return false;
    }
    pairing_message_.resize(size);
    return true;
}

bool PairingConnection::establishEncryption(const uint8_t* response, size_t size) {
    uint8_t keyMaterial[SPAKE2_MAX_KEY_SIZE];
    size_t keyLen = 0;
    int status = SPAKE2_process_msg(context_.get(),
                                    keyMaterial, &keyLen, sizeof(keyMaterial),
                                    response, size);
    if (status != 1) {
        terminate();
        return false;
    }

    if (!cipher_.init(keyMaterial, keyLen)) {
        terminate();
        return false;
    }
    return true;
}

bool PairingConnection::sendRawMsg(const uint8_t* data, uint32_t size) {
    uint32_t networkSize = htonl(size);
    if (!WriteFdExactly(fdevent_->fd, &networkSize, sizeof(networkSize))) {
        return false;
    }
    if (!WriteFdExactly(fdevent_->fd, data, size)) {
        return false;
    }
    return true;
}

bool PairingConnection::sendSecureMsg(const uint8_t* data, uint32_t size) {
    std::vector<uint8_t> encrypted(cipher_.encryptedSize(size));
    int bytes = cipher_.encrypt(data, size, encrypted.data(), encrypted.size());
    if (bytes < 0) {
        return false;
    }
    return WriteFdExactly(fdevent_->fd, encrypted.data(), bytes);
}

bool PairingConnection::authenticate() {
    LOG(ERROR) << "Attempting to authenticate";
    uint8_t auth[kMaxAuthMsgSize];
    int bytes = readAuthentication(auth);
    if (bytes < 0) {
        // Something went really wrong, connection closed
        terminate();
        return false;
    } else if (bytes == 0) {
        // Not enough data yet, wait
        return false;
    }
    if (!establishEncryption(auth, bytes)) {
        // Could not establish encryption, abandon this connection
        terminate();
        return false;
    }
    return true;
}

bool PairingConnection::sendPublicKey() {
    LOG(ERROR) << "Attempting send public key";
    KeyStore* keyStore = getKeyStore();
    if (!keyStore) {
        LOG(ERROR) << "Unable send public key: no key store";
        return false;
    }
    Key* key = keyStore->getSystemPublicKey(key_type_);
    if (!key) {
        LOG(ERROR) << "Unable send public key: no system public key";
        return false;
    }
    std::vector<uint8_t> msg(key->size() + sizeof(PublicKeyHeader));

    auto& header = *reinterpret_cast<PublicKeyHeader*>(msg.data());
    uint8_t* keyLocation = msg.data() + sizeof(PublicKeyHeader);
    header.version = kCurrentKeyHeaderVersion;
    header.type = static_cast<uint8_t>(key->type());;
    header.bits = htonl(key->bits());
    header.payload = htonl(key->size());
    strncpy(header.name, get_device_name().c_str(), sizeof(header.name));
    header.name[sizeof(header.name) - 1] = '\0';
    strncpy(header.id, get_unique_device_id().c_str(), sizeof(header.id));
    header.id[sizeof(header.id) - 1] = '\0';

    memcpy(keyLocation, key->c_str(), key->size());

    if (!sendSecureMsg(msg.data(), msg.size())) {
        LOG(ERROR) << "Unable send public key: failed to send secure message";
        terminate();
        return false;
    }
    return true;
}

// Safely extract the string from an array of data. If |data| does not contain
// a terminating null then the resulting string will be created from all the
// contents of |data| and a terminating null will be appended. If there is a
// terminating null in |data| the resulting string will be terminated at that
// the first null terminator.
static std::string getSafeString(const char* data, size_t length) {
    std::string result;
    if (::memchr(data, '\0', length) != nullptr) {
        result = data;
    } else {
        result.assign(data, length);
    }
    return result;
}

int PairingConnection::readPublicKey() {
    LOG(ERROR) << "Attempting to read public key";
    int requiredSize = cipher_.decryptedSize(rx_buffer_.data(),
                                             rx_buffer_.size());
    if (requiredSize == 0) {
        return 0;
    } else if (requiredSize < 0) {
        terminate();
        return -1;
    }
    std::vector<uint8_t> decrypted(requiredSize);
    size_t decryptedSize = decrypted.size();
    int bytes = cipher_.decrypt(rx_buffer_.data(), rx_buffer_.size(),
                                decrypted.data(), &decryptedSize);
    if (bytes == 0) {
        return 0;
    } else if (bytes < 0) {
        terminate();
        return -1;
    }

    rx_buffer_.erase(rx_buffer_.begin(),
                     rx_buffer_.begin() + static_cast<size_t>(bytes));
    if (decryptedSize == 0) {
        return 0;
    }
    decrypted.resize(decryptedSize);

    auto header = reinterpret_cast<const PublicKeyHeader*>(decrypted.data());
    const uint8_t* keyLocation = decrypted.data() + sizeof(PublicKeyHeader);

    if (header->version > kMaxSupportedKeyHeaderVersion ||
        header->version < kMinSupportedKeyHeaderVersion) {
        LOG(ERROR) << "Unsupported key header version " << header->version;
        terminate();
        return -1;
    }
    KeyType type;
    if (!getKeyTypeFromValue(header->type, &type)) {
        LOG(ERROR) << "Received unknown key type " << header->type;
        terminate();
        return -1;
    }

    std::string id = getSafeString(header->id, sizeof(header->id));
    std::string name = getSafeString(header->name, sizeof(header->name));

    uint32_t keyLength = ntohl(header->payload);
    std::string key = getSafeString(reinterpret_cast<const char*>(keyLocation),
                                    keyLength);

    KeyStore* keyStore = getKeyStore();
    if (!keyStore) {
        terminate();
        return -1;
    }

    keyStore->storePublicKey(id, name, type, key);

    return bytes;
}

void PairingConnection::terminate() {
    LOG(ERROR) << "PairingConnection::terminate called";
    check_main_thread();
    LOG(ERROR) << "PairingConnection::terminate on main thread";
    state_ = State::Terminated;
    callback_(false);
}

void PairingConnection::staticOnFdEvent(int fd, unsigned ev, void* data) {
    if (ev & FDE_ERROR) {
        return;
    }
    auto connection = reinterpret_cast<PairingConnection*>(data);
    connection->onFdEvent(fd, ev);
}

void PairingConnection::onFdEvent(int fd, unsigned ev) {
    LOG(ERROR) << "PairingConnection::onFdEvent called with ev: 0x" << std::hex << ev;
    check_main_thread();
    LOG(ERROR) << "PairingConnection::onFdEvent on main thread";

    if ((ev & FDE_READ) == 0 || fd != fdevent_->fd) {
        return;
    }

    if (!receive()) {
        return;
    }

    while (true) {
        switch (state_) {
            case State::Connected:
                if (authenticate()) {
                    state_ = State::SendingPublicKey;
                    continue;
                }
                break;
            case State::SendingPublicKey:
                if (sendPublicKey()) {
                    state_ = State::Authenticated;
                    if (!rx_buffer_.empty()) {
                        // There's more data to process, keep going
                        continue;
                    }
                }
                break;
            case State::Authenticated:
                if (readPublicKey() > 0) {
                    state_ = State::Completed;
                    callback_(true);
                }
                break;
            default:
                // Unexpected state, we shouldn't receive anything here
                LOG(ERROR) << "received data in unexpected state "
                           << static_cast<int>(state_);
                terminate();
        }
        // At this point there's no more data to process
        break;
    }
}

