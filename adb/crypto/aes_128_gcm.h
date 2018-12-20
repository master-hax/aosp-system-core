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

#include <openssl/aes.h>
#include <openssl/cipher.h>

#include <stdint.h>

#include "crypto/counter.h"

// This is the default size of the initialization vector (iv) for AES-128-GCM
#define AES_128_GCM_IV_SIZE 12
// This is the full tag size for AES-128-GCM
#define AES_128_GCM_TAG_SIZE 16

namespace crypto {

class Aes128Gcm {
public:
    bool init(const uint8_t* keyMaterial, size_t keyMaterialLen);

    // Encrypt a block of data in |in| of length |inLen|, this consumes all data
    // in |in| and places the encrypted data in |out| if |outLen| indicates that
    // there is enough space. The data contains information needed for
    // decryption that is specific to this implementation and is therefore only
    // suitable for decryption with this class.
    // The method returns the number of bytes placed in |out| on success and a
    // negative value if an error occurs.
    int encrypt(const uint8_t* in, size_t inLen, uint8_t* out, size_t outLen);
    // Decrypt a block of data in |in| of length |inLen|, this may not consume
    // all |inLen| bytes of data, just enough to consume one block. The
    // decrypted output is placed in the |out| buffer of length |outLen|. On
    // successful decryption the number of bytes in |out| will be placed in
    // |outLen|. 
    // The method returns the number of bytes consumed from the |in| buffer. If
    // there is not enough data available in |in| the method returns zero. If
    // an error occurs the method returns a negative value.
    int decrypt(const uint8_t* in, size_t inLen, uint8_t* out, size_t* outLen);

    // Return a safe amount of buffer storage needed to encrypt |size| bytes.
    size_t encryptedSize(size_t size);
    // Return a safe amount of buffer storage needed to decrypt the encrypted
    // data in |encryptedData| which is of length |encryptedSize|. Returns 0 if
    // there is not enough data available to determine the required size.
    // Returns a negative value on failure.
    int decryptedSize(const uint8_t* encryptedData, size_t encryptedSize);


private:
    bssl::UniquePtr<EVP_CIPHER_CTX> mContext;
    AES_KEY mAesKey;
    // We're going to use this counter for our iv so that it never repeats
    Counter<AES_128_GCM_IV_SIZE> mCounter;
    bool mInitialized = false;
};

}  // namespace crypto
