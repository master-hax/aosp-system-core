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

#include <gtest/gtest.h>
#include <openssl/rand.h>

namespace crypto {

TEST(aes_128_gcm, init) {
    uint8_t material[64];
    Aes128Gcm cipher;
    EXPECT_TRUE(cipher.init(material, sizeof(material)));
}

TEST(aes_128_gcm, init_twice) {
    uint8_t material[64];
    Aes128Gcm cipher;
    ASSERT_TRUE(cipher.init(material, sizeof(material)));
    EXPECT_FALSE(cipher.init(material, sizeof(material)));
}

TEST(aes_128_gcm, init_null_material) {
    Aes128Gcm cipher;
    EXPECT_FALSE(cipher.init(nullptr, 42));
}

TEST(aes_128_gcm, init_empty_material) {
    uint8_t material[64];
    Aes128Gcm cipher;
    EXPECT_FALSE(cipher.init(material, 0));
}

TEST(aes_128_gcm, encrypt_decrypt) {
    const uint8_t secretMessage[] = "alice and bob, sitting in a binary tree";
    uint8_t material[256];
    uint8_t encrypted[1024];
    uint8_t decrypted[1024];

    Aes128Gcm alice, bob;
    RAND_bytes(material, sizeof(material));

    ASSERT_TRUE(alice.init(material, sizeof(material)));
    ASSERT_TRUE(bob.init(material, sizeof(material)));

    int encryptedSize = alice.encrypt(secretMessage, sizeof(secretMessage),
                                      encrypted, sizeof(encrypted));
    ASSERT_GT(encryptedSize, 0);
    size_t decryptedSize = sizeof(decrypted);
    int consumedBytes = bob.decrypt(encrypted, sizeof(encrypted),
                                    decrypted, &decryptedSize);
    ASSERT_EQ(encryptedSize, consumedBytes);
    ASSERT_STREQ(reinterpret_cast<const char*>(secretMessage),
                 reinterpret_cast<const char*>(decrypted));
}

}  // namespace crypto

