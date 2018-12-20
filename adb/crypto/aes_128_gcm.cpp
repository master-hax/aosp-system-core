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

#include "aes_128_gcm.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>

#include "sysdeps.h"

namespace crypto {

static const size_t kHkdfKeyLength = 256;

struct Header {
    uint32_t length;
    uint8_t iv[AES_128_GCM_IV_SIZE];
    uint8_t tag[AES_128_GCM_TAG_SIZE];
} __attribute__((packed));

bool Aes128Gcm::init(const uint8_t* keyMaterial, size_t keyMaterialLen) {
    if (keyMaterial == nullptr || keyMaterialLen == 0 || mInitialized) {
        return false;
    }
    mContext.reset(EVP_CIPHER_CTX_new());
    if (mContext.get() == nullptr) {
        return false;
    }

    // Start with a random number for our counter
    int status = RAND_bytes(mCounter.data(), mCounter.size());
    if (status != 1) {
        return false;
    }

    uint8_t key[kHkdfKeyLength] = {};
    uint8_t salt[64] = "this is the salt";
    uint8_t info[64] = "this is the info";
    status = HKDF(key, sizeof(key), EVP_sha256(),
                  keyMaterial, keyMaterialLen,
                  salt, sizeof(salt),
                  info, sizeof(info));
    if (status != 1) {
        return false;
    }
    if (AES_set_encrypt_key(key, sizeof(key), &mAesKey) != 0) {
        return false;
    }
    mInitialized = true;
    return true;
}

int Aes128Gcm::encrypt(const uint8_t* in, size_t inLen,
                       uint8_t* out, size_t outLen) {
    if (outLen < inLen + sizeof(Header)) {
        return -1;
    }
    auto& header = *reinterpret_cast<Header*>(out);
    // Place the IV in the header
    memcpy(header.iv, mCounter.data(), mCounter.size());
    int status = EVP_EncryptInit_ex(mContext.get(),
                                    EVP_aes_128_gcm(),
                                    nullptr,
                                    reinterpret_cast<const uint8_t*>(&mAesKey),
                                    mCounter.data());
    mCounter.increase();
    if (status != 1) {
        return -1;
    }

    int cipherLen = 0;
    out += sizeof(header);
    status = EVP_EncryptUpdate(mContext.get(), out, &cipherLen, in, inLen);
    if (status != 1 || cipherLen < 0) {
        return -1;
    }
    int len = 0;
    status = EVP_EncryptFinal_ex(mContext.get(), out + cipherLen, &len);
    if (status != 1 || len < 0) {
        return -1;
    }
    // Place the tag in the header
    status = EVP_CIPHER_CTX_ctrl(mContext.get(), EVP_CTRL_GCM_GET_TAG,
                                 sizeof(header.tag), header.tag);
    if (status != 1) {
        return -1;
    }
    // Place the length in the header
    uint32_t headerLen = sizeof(header) + cipherLen + len;
    header.length = htonl(headerLen);
    return headerLen;
}

int Aes128Gcm::decrypt(const uint8_t* in, size_t inLen,
                       uint8_t* out, size_t* outLen) {
    if (inLen < sizeof(Header)) {
        return 0;
    }
    const auto& header = *reinterpret_cast<const Header*>(in);
    uint32_t headerLen = ntohl(header.length);
    if (inLen < headerLen) {
        // Not enough data available
        return 0;
    }
    // Initialized with expected IV from header
    int status = EVP_DecryptInit_ex(mContext.get(),
                                    EVP_aes_128_gcm(),
                                    nullptr,
                                    reinterpret_cast<const uint8_t*>(&mAesKey),
                                    header.iv);
    if (status != 1) {
        return -1;
    }

    int plaintextLen = 0;
    size_t cipherLen = headerLen - sizeof(header);
    status = EVP_DecryptUpdate(mContext.get(), out, &plaintextLen,
                               in + sizeof(header), cipherLen);
    if (status != 1 || plaintextLen < 0) {
        return -1;
    }

    // Set expected tag from header
    status = EVP_CIPHER_CTX_ctrl(mContext.get(),
                                 EVP_CTRL_GCM_SET_TAG,
                                 sizeof(header.tag),
                                 const_cast<uint8_t*>(header.tag));
    if (status != 1) {
        return -1;
    }

    int len = 0;
    status = EVP_DecryptFinal_ex(mContext.get(), out + plaintextLen, &len);
    if (status != 1) {
        return -1;
    }
    *outLen = plaintextLen + len;
    return headerLen;
}

size_t Aes128Gcm::encryptedSize(size_t size) {
    return size + sizeof(Header);
}

int Aes128Gcm::decryptedSize(const uint8_t* encryptedData,
                             size_t encryptedSize) {
    if (encryptedSize < sizeof(Header)) {
        // Not enough data yet
        return 0;
    }
    auto header = reinterpret_cast<const Header*>(encryptedData);
    uint32_t length = ntohl(header->length);
    if (encryptedSize < length) {
        // There's enough data for the header but not enough data for theo
        // payload. Indicate that there's not enough data for now.
        return 0;
    }
    return length;
}

}  // namespace crypto
