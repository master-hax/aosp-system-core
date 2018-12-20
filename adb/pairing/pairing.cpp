/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "pairing.h"

#include "crypto/key_store.h"
#include "pairing/pairing_client.h"
#include "pairing/pairing_server.h"
#if !ADB_HOST
#include "daemon/wireless_debug_service.h"
#endif

#include <mutex>

#include <android-base/logging.h>
#include <openssl/rand.h>

static constexpr int kDefaultPairingPort = 51393;

#if ADB_HOST

void pair_device(const std::string& host,
                 const std::string& password,
                 std::string* response) {
    std::condition_variable cv;
    std::mutex mutex;
    bool success = false;
    auto callback = [&](bool result) {
        LOG(ERROR) << "receiving pair_device callback";
        std::unique_lock<std::mutex> lock(mutex);
        success = result;
        cv.notify_all();
    };
    PairingClient client(password, callback);

    std::unique_lock<std::mutex> lock(mutex);
    fdevent_run_on_main_thread([&]() {
        LOG(ERROR) << "pair_device connecting";
        if (!client.connect(host, kDefaultPairingPort, response)) {
            LOG(ERROR) << "pair_device connet failed, calling callback";
            callback(false);
            return;
        }
    });
    LOG(ERROR) << "pair_device waiting for cv";
    cv.wait(lock);
    LOG(ERROR) << "pair_device triggered on cv";
    if (success) {
        *response = "successfully paired with " + host;
    } else {
        *response = "failed to pair with " + host;
    }
    LOG(ERROR) << "pair_device done, returning";
}

#else

static PairingServer* sPairingServer = nullptr;

static const char kBase32EncodingTable[] = {
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
    'q','r','s','t','u','v','w','x','y','z','2','3','4','5','6','7'};

std::string base32Encode(const unsigned char* data, size_t size) {
    std::string result;
    if (size == 0) {
        return result;
    }
    unsigned int bitOffset = 0;
    for (size_t byteOffset = 0; byteOffset < size; ) {
        unsigned int mask = (1u << (8u - bitOffset)) - 1u;
        unsigned char value = (data[byteOffset] & mask);
        if (bitOffset < 4) {
            value = value >> (3u - bitOffset);
        } else {
            value = data[byteOffset] & mask;
            if (byteOffset + 1 < size) {
                unsigned int leftShift = bitOffset - 3;
                unsigned int rightShift = 8 - leftShift;
                value = (value << leftShift) |
                        (data[byteOffset + 1] >> rightShift);
            }
        }
        result += kBase32EncodingTable[value];
        bitOffset += 5;
        if (bitOffset >= 8) {
            ++byteOffset;
            bitOffset -= 8;
        }
    }
    return result;
}

static std::string generatePairingCode() {
    unsigned char codeData[5];
    RAND_bytes(codeData, sizeof(codeData));
    std::string pairingCode = base32Encode(codeData, sizeof(codeData));
    // Ensure we always have an 8 character pairing code, add leading 'a' which
    // is the zero value for base32 encoding.
    if (pairingCode.size() < 8) {
        pairingCode.insert(0, 8 - pairingCode.size(), 'a');
    }
    return pairingCode;
}

static void onResult(bool ok) {
    LOG(ERROR) << "Pairing " << (ok ? "succeeded" : "failed");
    if (ok) {
        // Immediately stop other pairing attempts if this was successful
        pair_cancel();
    }
    const char* status = ok ? ADB_WIRELESS_STATUS_OK : ADB_WIRELESS_STATUS_FAIL;
    adbd_wireless_send_pair_unpair_result(true, status, 0);
    if (ok) {
        std::string devices = get_paired_devices();
        if (!devices.empty()) {
            adbd_wireless_send_paired_devices(devices);
        }
    }
}

std::string pair_host() {
    LOG(ERROR) << "pair_host called";
    if (sPairingServer) {
        delete sPairingServer;
    }

    std::string password = generatePairingCode();
    if (password.empty()) {
        LOG(ERROR) << "Failed to generate pairing code";
        return std::string();
    }
    LOG(ERROR) << "pair_host allocating pairing server";
    sPairingServer = new PairingServer(password, &onResult);
    if (!sPairingServer) {
        LOG(ERROR) << "Failed to allocate memory for pairing";
        return std::string();
    }

    std::string response;
    if (!sPairingServer->listen(&response, kDefaultPairingPort)) {
        LOG(ERROR) << "Failed to listen for pairings: " << response;
        delete sPairingServer;
        return std::string();
    }
    return password;
}

void pair_cancel() {
    delete sPairingServer;
    sPairingServer = nullptr;
}

std::string get_paired_devices() {
    KeyStore* keyStore = getKeyStore();
    if (keyStore == nullptr) {
        LOG(ERROR) << "Failed to get list of paired devices, keystore not initialized";
        return std::string();
    }

    std::string result;
    for (size_t i = 0; i < keyStore->size(); ++i) {
        std::pair<std::string, const Key*> idKey = (*keyStore)[i];
        std::string line = std::to_string(i) + '\n' +
                           idKey.second->name() + '\n' +
                           std::string("00:11:22:33:44:55\n") +
                           std::string("0");
        if (i != keyStore->size() -1) {
            line += '\n';
        }

        result += line;
    }
    return result;
}

#endif

