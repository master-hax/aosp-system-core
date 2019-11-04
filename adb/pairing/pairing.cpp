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
#if ADB_HOST
#include "pairing/pairing_client.h"
#else
#include "pairing/pairing_server.h"
#endif
#include "adb_wifi.h"

#include <mutex>

#include <android-base/logging.h>
#include <openssl/rand.h>

#if ADB_HOST

void pair_device(const std::string& host,
                 const std::string& password,
                 std::string* response) {
    LOG(INFO) << "pair_device(host=[" << host << "], "
              << "password=[" << password << "])";
    if (password.empty()) {
        LOG(ERROR) << "Client sent an empty password";
        return;
    }

    std::condition_variable cv;
    std::mutex mutex;
    bool success = false;
    // |callback| will block this function until the pairing completes.
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
        // Pass a callback here to notify completion and to clean up sClient
        if (!client.connect(host, ADB_WIFI_PAIRING_PORT, response)) {
            LOG(ERROR) << "pair_device connect failed, calling callback";
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

bool pair_host(const uint8_t* publicKey, uint64_t sz) {
    LOG(ERROR) << "pair_host called";
    if (sPairingServer != nullptr) {
        delete sPairingServer;
    }

    LOG(ERROR) << "pair_host allocating pairing server";
    sPairingServer = new PairingServer(publicKey, sz);

    std::string response;
    if (!sPairingServer->listen(&response, ADB_WIFI_PAIRING_PORT)) {
        LOG(ERROR) << "Failed to listen for pairings: " << response;
        delete sPairingServer;
        return false;
    }
    return true;
}

void pair_host_send_pairing_request(const uint8_t* pairing_request,
                                    uint64_t sz) {
    LOG(INFO) << "Got pairing request from system server.";
    if (sPairingServer == nullptr) {
        LOG(ERROR) << "Pairing server not created. Can't send the pairing request.";
        return;
    }

    sPairingServer->sendPairingRequest(pairing_request, sz);
}

void pair_cancel() {
    if (sPairingServer != nullptr) {
        delete sPairingServer;
    }
    sPairingServer = nullptr;
}

// TODO: move into system server
//std::string get_paired_devices() {
//    KeyStore* keyStore = getKeyStore();
//    if (keyStore == nullptr) {
//        LOG(ERROR) << "Failed to get list of paired devices, keystore not initialized";
//        return std::string();
//    }
//
//    std::string result;
//    for (size_t i = 0; i < keyStore->size(); ++i) {
//        std::pair<std::string, const Key*> idKey = (*keyStore)[i];
//        std::string line = std::to_string(i) + '\n' +
//                           idKey.second->name() + '\n' +
//                           std::string("00:11:22:33:44:55\n") +
//                           std::string("0");
//        if (i != keyStore->size() -1) {
//            line += '\n';
//        }
//
//        result += line;
//    }
//    return result;
//}

#endif

