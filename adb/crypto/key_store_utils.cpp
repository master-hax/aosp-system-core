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

#include "key_store_utils.h"

#include "key_store.h"

#include <android-base/logging.h>

#include <thread>

static KeyStore* sKeyStore = nullptr;

#if !ADB_HOST
using namespace std::chrono_literals;

void retryKeyStoreInitLoop() {
    do {
        LOG(ERROR) << "keystore init retry loop sleeping";
        std::this_thread::sleep_for(1s);
    } while (!sKeyStore->init());
    LOG(ERROR) << "keystore init retry loop succeeded";
}
#endif // !ADB_HOST

bool initKeyStore() {
    if (sKeyStore) {
        return true;
    }
    sKeyStore = new KeyStore;
    if (!sKeyStore) {
        LOG(ERROR) << "Failed to allocate memory for keystore";
        return false;
    }
    bool success = sKeyStore->init();
    if (success) {
        return true;
    }
#if !ADB_HOST
    // We failed to initialize, this might be normal on first boot because the
    // directory where keys are stored might not exist yet and adb is started
    // before the filesystem comes up. Try again later.
    LOG(ERROR) << "key store init failed, launching retry thread";
    std::thread(&retryKeyStoreInitLoop).detach();
#endif // !ADB_HOST
    return false;
}

KeyStore* getKeyStore() {
    return sKeyStore;
}

