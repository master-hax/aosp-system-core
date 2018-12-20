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

#include "key.h"
#include "key_type.h"

#include <memory>
#include <string>
#include <unordered_map>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

static constexpr size_t kPublicKeyNameLength = 128;
static constexpr size_t kPublicKeyIdLength = 128;

class KeyStore {
public:
    bool init();

    // Get the system's public key if one exists, if it does not exist nullptr
    // is returned.
    Key* getSystemPublicKey(KeyType type = KeyType::EllipticCurve);

    // Store the public |key| of another system, the key is of |type| and
    // associated with the device/system identified by |identifier| and with the
    // user friendly display name |name|.
    bool storePublicKey(const std::string& identifier,
                        const std::string& name,
                        KeyType type,
                        const std::string& key);

    // Get the public |key|, |name| and |type| associated with the device/system
    // identified by |identifier|.
    bool getPublicKey(const std::string& identifier,
                      std::string* name,
                      KeyType* type,
                      std::string* key);

    size_t size() const { return keys_.size(); }
    std::pair<std::string, const Key*> operator[](const size_t idx) const;


private:
    bool generateSystemCertificate(KeyType type = KeyType::EllipticCurve);

    bool readSystemCertificate();
    bool writeSystemCertificate();
    bool readPublicKeys();
    bool writePublicKeys();

    std::unordered_map<std::string, std::unique_ptr<Key>> keys_;
    bssl::UniquePtr<EVP_PKEY> evp_pkey_;
    bssl::UniquePtr<X509> x509_;
    std::unique_ptr<Key> private_key_;
    std::unique_ptr<Key> public_cert_;
};

bool initKeyStore();
KeyStore* getKeyStore();
