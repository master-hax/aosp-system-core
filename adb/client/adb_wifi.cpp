/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

#include "adb_wifi.h"

#include <thread>
#include <random>

#include <adbwifi/crypto/device_identifier.h>
#include <adbwifi/crypto/key_store.h>
#include <adbwifi/pairing/pairing_client.h>

#include "adb_utils.h"
#include "client/adb_client.h"
#include "sysdeps.h"

using adbwifi::crypto::DeviceIdentifier;
using adbwifi::crypto::KeyStore;
using adbwifi::pairing::PairingClient;

static std::string randomAlphaNumString(size_t len) {
    std::string ret;
    std::random_device rd;
    std::mt19937 mt(rd());
    // Generate values starting with zero and then up to enough to cover numeric
    // digits, small letters and capital letters (26 each).
    std::uniform_int_distribution<uint8_t> dist(0, 61);
    for (size_t i = 0; i < len; ++i) {
        uint8_t val = dist(mt);
        if (val < 10) {
            ret += '0' + val;
        } else if (val < 36) {
            ret += 'A' + (val - 10);
        } else {
            ret += 'a' + (val - 36);
        }
    }
    return ret;
}

static std::string generateDeviceGuid() {
    // Format is "<hostname>-<six-random-alphanum>"
    std::string guid;

    char hostname_buf[128] = {};
    if (adb_gethostname(hostname_buf, 128) != 0) {
        LOG(ERROR) << __func__ <<  ": adb_gethostname failed";
        // Let's just fill 16 byte random string of characters
        guid += randomAlphaNumString(16);
    } else {
        guid += hostname_buf;
    }

    guid += '-';

    // generate the six-digit suffix
    guid += randomAlphaNumString(6);
    return guid;
}

void adb_wifi_init() {
    // Generate adb_device_id if none exists.
    DeviceIdentifier device_id(adb_get_android_dir_path());
    if (device_id.getUniqueDeviceId().empty()) {
        LOG(INFO) << "adbwifi device id does not exist. Creating one.";
        device_id.resetUniqueDeviceId(generateDeviceGuid());
    }
}

static std::vector<uint8_t> stringToUint8(const std::string& str) {
    auto* p8 = reinterpret_cast<const uint8_t*>(str.data());
    return std::vector<uint8_t>(p8, p8 + str.length());
}

void adb_wifi_pair_device(const std::string& host,
                          const std::string& password,
                          std::string& response) {
    // Get the system keys for the pairing client
    auto key_store = KeyStore::create(adb_get_android_dir_path());
    if (key_store == nullptr) {
        response = "Unable to create keystore for TLS handshake.";
        return;
    }
    auto device_info = key_store->getDeviceInfo();
    if (!device_info.has_value()) {
        response = "Unable to obtain system keys for tls connection.";
        return;
    }
    auto [sys_guid, sys_name, sys_cert, sys_priv_key] = *device_info;
    adbwifi::pairing::PeerInfo system_info = {};
    memcpy(system_info.guid, sys_guid.data(), std::min(adbwifi::pairing::kPeerGuidLength, sys_guid.size()));
    memcpy(system_info.name, sys_name.data(), std::min(adbwifi::pairing::kPeerNameLength, sys_name.size()));

    auto pswd8 = stringToUint8(password);
    auto cert8 = stringToUint8(sys_cert);
    auto priv8 = stringToUint8(sys_priv_key);

    auto client = PairingClient::create(pswd8,
                                        system_info,
                                        cert8,
                                        priv8,
                                        host);
    if (client == nullptr) {
        response = "Failed: unable to create pairing client.";
        return;
    }

    // This is a blocking call. It will block until we get a result back from
    // the pairing.
    std::mutex mutex;
    std::condition_variable cv;
    std::string guid;
    std::optional<bool> got_pairing;
    std::unique_lock<std::mutex> lock(mutex);
    auto callback = [&](const adbwifi::pairing::PeerInfo* peer_info,
                        const adbwifi::pairing::PairingConnection::Data* cert,
                        void* /* opaque */) {
        if (peer_info != nullptr && cert != nullptr) {
            // Save in the keystore
            auto key_info = std::make_tuple(std::string(peer_info->guid),
                                            std::string(peer_info->name),
                                            std::string(reinterpret_cast<const char*>(cert->data())));
            if (!key_store->storePeerInfo(std::move(key_info))) {
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    response = "Failed: unable to store the certificate.";
                    got_pairing = false;
                }
                cv.notify_one();
                return;
            }
            {
                std::lock_guard<std::mutex> lock(mutex);
                response = "Successfully paired to " + host + " [name=" + peer_info->name
                         + ", guid=" + peer_info->guid + "]";
                guid = peer_info->guid;
                got_pairing = true;
            }
            cv.notify_one();
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mutex);
            response = "Failed: Wrong password or connection was dropped.";
            got_pairing = false;
        }
        cv.notify_one();
    };
    if (!client->start(callback, nullptr)) {
        response = "Failed: Unable to start pairing client.";
        return;
    }

    LOG(INFO) << "Waiting for pairing client to complete";
    cv.wait(lock, [&]() { return got_pairing.has_value(); });
    LOG(INFO) << "Pairing client completed";
    if (*got_pairing) {
        // Try to auto-connect. Do it on a separate thread to avoid blocking the
        // client.
        std::thread([guid]() { adb_secure_connect_by_service_name(guid.c_str()); }).detach();
    }
}
