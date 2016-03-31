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

// This file implements encoding and decoding logic for Android's custom RSA
// public key binary format. Public keys are stored as a sequence of
// little-endian 32 bit words:
//
//   typedef struct RSAPublicKey {
//       uint32_t len;       // Length of n[] in number of uint32_t
//       uint32_t n0inv;     // -1 / n[0] mod 2^32
//       uint32_t n[len];    // modulus as little endian array
//       uint32_t rr[len];   // R^2 as little endian array
//       uint32_t exponent;  // 3 or 65537
//   } RSAPublicKey;
//
// Note that Android only supports little-endian processors, we don't do any
// byte order conversions when parsing the binary struct.

#include <crypto_utils/android_pubkey.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

// Maximum supported RSA modulus size in bits.
static const uint32_t kMaxRsaBitSize = 8192;

// Reverses byte order in |buffer|.
static void reverse_bytes(uint8_t* buffer, size_t size) {
  for (size_t i = 0; i < (size + 1) / 2; ++i) {
    uint8_t tmp = buffer[i];
    buffer[i] = buffer[size - i - 1];
    buffer[size - i - 1] = tmp;
  }
}

size_t android_pubkey_decode(const uint8_t* key_buffer,
                             size_t size,
                             RSA** key) {
  const uint32_t* key_words = (const uint32_t*)key_buffer;
  int ret = 0;
  uint8_t* modulus_buffer = NULL;
  RSA* new_key = RSA_new();
  if (!new_key) {
    goto cleanup;
  }

  // Check |size| is valid w.r.t. to the encoded RSA modulus size.
  if (size < sizeof(uint32_t)) {
    goto cleanup;
  }
  const uint32_t modulus_size_words = *key_words++;
  if (modulus_size_words > kMaxRsaBitSize / 32||
      size < ANDROID_PUBKEY_ENCODED_SIZE(modulus_size_words * 32)) {
    goto cleanup;
  }

  // Skip n0inv. We don't extract the montgomery parameters n0inv and rr from
  // the RSAPublicKey structure. They assume a word size of 32 bits, but
  // BoringSSL may use a word size of 64 bits internally, so we're lacking the
  // top 32 bits of n0inv in general. For now, we just ignore the parameters
  // and have BoringSSL recompute them internally. More sophisticated logic can
  // be added here if/when we want the additional speedup from using the
  // pre-computed montgomery parameters.
  ++key_words;

  // Allocate a buffer for the modulus and convert to big-endian binary format
  // suitable for passing to BN_bin2bn.
  const size_t modulus_size_bytes = modulus_size_words * sizeof(uint32_t);
  modulus_buffer = malloc(modulus_size_bytes);
  if (!modulus_buffer) {
    goto cleanup;
  }
  memcpy(modulus_buffer, key_words, modulus_size_bytes);
  key_words += modulus_size_words;
  reverse_bytes(modulus_buffer, modulus_size_bytes);
  new_key->n = BN_bin2bn(modulus_buffer, modulus_size_bytes, NULL);
  if (!new_key->n) {
    goto cleanup;
  }

  // Skip rr (montgomery parameter).
  key_words += modulus_size_words;

  // Read the exponent.
  new_key->e = BN_new();
  if (!new_key->e || !BN_set_word(new_key->e, *key_words++)) {
    goto cleanup;
  }

  *key = new_key;
  ret = ((uint8_t*)key_words) - key_buffer;

  // Buffer overflow sanity check.
  assert(ret <= size);

cleanup:
  free(modulus_buffer);
  if (!ret && new_key) {
    RSA_free(new_key);
  }
  return ret;
}

static int android_pubkey_encode_bignum(const BIGNUM* num,
                                        uint8_t* buffer,
                                        size_t size) {
  if (!BN_bn2bin_padded(buffer, size, num)) {
    return 0;
  }

  reverse_bytes(buffer, size);
  return 1;
}

size_t android_pubkey_encode(const RSA* key, uint8_t* key_buffer, size_t size) {
  uint32_t* key_words = (uint32_t*)key_buffer;
  int ret = 0;
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* r32 = BN_new();
  BIGNUM* n0inv = BN_new();
  BIGNUM* rr = BN_new();

  if (ANDROID_PUBKEY_ENCODED_SIZE_FOR_KEY(key) > size) {
    goto cleanup;
  }

  // Store the modulus size.
  uint32_t modulus_size_words =
      (ANDROID_PUBKEY_MODULUS_SIZE_FOR_KEY(key) + 3) / 4;
  *key_words++ = modulus_size_words;

  // Compute and store n0inv = -1 / N[0] mod 2^32.
  if (!ctx || !r32 || !n0inv || !BN_set_bit(r32, 32) ||
      !BN_mod(n0inv, key->n, r32, ctx) ||
      !BN_mod_inverse(n0inv, n0inv, r32, ctx) || !BN_sub(n0inv, r32, n0inv)) {
    goto cleanup;
  }
  *key_words++ = (uint32_t)BN_get_word(n0inv);

  // Store the modulus.
  if (!android_pubkey_encode_bignum(key->n, (uint8_t*)key_words,
                                    modulus_size_words * sizeof(uint32_t))) {
    goto cleanup;
  }
  key_words += modulus_size_words;

  // Compute and store rr = (2^(rsa_size)) ^ 2 mod N.
  if (!ctx || !rr || !BN_set_bit(rr, modulus_size_words * 32) ||
      !BN_mod_sqr(rr, rr, key->n, ctx) ||
      !android_pubkey_encode_bignum(rr, (uint8_t*)key_words,
                                    modulus_size_words * sizeof(uint32_t))) {
    goto cleanup;
  }
  key_words += modulus_size_words;

  // Store the exponent.
  *key_words++ = (uint32_t) BN_get_word(key->e);

  ret = ((uint8_t*)key_words) - key_buffer;

  // Sanity check for buffer overflow.
  assert(ret == ANDROID_PUBKEY_ENCODED_SIZE_FOR_KEY(key));

cleanup:
  BN_free(rr);
  BN_free(n0inv);
  BN_free(r32);
  BN_CTX_free(ctx);
  return ret;
}
