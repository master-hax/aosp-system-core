/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef CRYPTO_UTILS_ANDROID_PUBKEY_H
#define CRYPTO_UTILS_ANDROID_PUBKEY_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/rsa.h>

#ifdef __cplusplus
extern "C" {
#endif

// Convenience macros for determining the size of a public RSA key encoded in
// Androids binary public key format.
#define ANDROID_PUBKEY_ENCODED_SIZE(bits) \
  ((3 + 2 * ((bits + 31) / 32)) * sizeof(uint32_t))
#define ANDROID_PUBKEY_ENCODED_SIZE_FOR_KEY(rsa_key) \
  ANDROID_PUBKEY_ENCODED_SIZE(RSA_size(rsa_key) * 8)

// Returns the byte size of an RSA modulus. Buffers of this size are suitable
// for storing the public modulus, one encrypted block, or a signature.
#define ANDROID_PUBKEY_MODULUS_SIZE(bits) ((bits + 7) / 8)
#define ANDROID_PUBKEY_MODULUS_SIZE_FOR_KEY(rsa_key) \
  ANDROID_PUBKEY_MODULUS_SIZE(RSA_size(rsa_key) * 8)

/* Allocates a new RSA |key| object, decodes a public RSA key stored in
 * Android's custom binary format from |key_buffer| and sets the key parameters
 * in |key|. The key can then be used with the standard BoringSSL API to perform
 * public operations.
 *
 * Returns the number of bytes decoded if successful, in which case the caller
 * receives ownership of the |*key| object, i.e. needs to call RSA_free() when
 * done with it. If there is an error, |key| is left untouched and the return
 * value will be 0.
 */
size_t android_pubkey_decode(const uint8_t* key_buffer, size_t size, RSA** key);

/* Encodes |key| in the Android RSA public key binary format and stores the
 * bytes in |key_buffer|. |key_buffer| should be of size at least
 * |ANDROID_PUBKEY_ENCODED_SIZE_FOR_KEY(key)|.
 *
 * Returns the number of bytes stored on success, which will be
 * |ANDROID_PUBKEY_ENCODED_SIZE_FOR_KEY(key)|. Returns 0 on error.
 */
size_t android_pubkey_encode(const RSA* key, uint8_t* key_buffer, size_t size);

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // CRYPTO_UTILS_ANDROID_PUBKEY_H
