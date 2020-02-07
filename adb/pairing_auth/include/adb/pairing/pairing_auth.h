/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <stddef.h>
#include <stdint.h>

extern "C" {

// PairingAuthCtx is a wrapper around the SPAKE2 protocol + cipher initialization
// for encryption. On construction, the |password| will be used to generate a
// SPAKE2 message. Each peer will exchange the messages in |pairing_auth_get_msg|
// to initialize their ciphers in |pairing_auth_init_cipher|. If both peers used the
// same |password|, then both sides will be able to decrypt each other's messages.
//
// On creation of a PairingAuthCtx, |pairing_auth_init_cipher| prior to using
// the encrypt and decrypt APIs. Furthermore, you can only initialize the cipher
// once.
//
// See pairing_auth_test.cpp for example usage.
//
struct PairingAuthCtx;

// Creates a new PairingAuthCtx instance as the server.
PairingAuthCtx* pairing_auth_server_new(const uint8_t* pswd, size_t len);

// Creates a new PairingAuthCtx instance as the client.
PairingAuthCtx* pairing_auth_client_new(const uint8_t* pswd, size_t len);

// Destroys the PairingAuthCtx.
void pairing_auth_destroy(PairingAuthCtx* ctx);

// Returns the exact size of the SPAKE2 msg. Use this size as the buffer size
// when retrieving the message via |pairing_auth_get_msg|.
size_t pairing_auth_msg_size(PairingAuthCtx* ctx);

// Writes the message to exchange with the other party in |out_buf|. This is
// guaranteed to have a valid message if PairingAuthCtx is valid. Use
// |pairing_auth_msg_size| to get the size the |out_buf| should be.
void pairing_auth_get_msg(PairingAuthCtx* ctx, uint8_t* out_buf);

// Processes the peer's |their_msg| and attempts to initialize the cipher for
// encryption. You can only call this method ONCE with a non-empty |msg|,
// regardless of success or failure. Subsequent calls will always return
// false. On success, you can use the |pairing_auth_decrypt|
// and |pairing_auth_encrypt| methods to exchange any further information securely.
//
// Note: Once you call this with a non-empty key, the state is locked, which
// means that you cannot try and register another key, regardless of the
// return value. In order to register another key, you have to create a new
// instance of PairingAuthCtx.
bool pairing_auth_init_cipher(PairingAuthCtx* ctx, const uint8_t* their_msg, size_t msg_len);

// Returns a safe buffer size for encrypting a buffer of size |len|.
size_t pairing_auth_safe_encrypted_size(PairingAuthCtx* ctx, size_t len);

// Encrypts |inbuf| and writes result to |outbuf|. If encryption fails, the return
// will be false, otherwise true.
bool pairing_auth_encrypt(PairingAuthCtx* ctx, const uint8_t* inbuf, size_t inlen, uint8_t* outbuf,
                          size_t* outlen);

// Returns a safe buffer size for decrypting a buffer |buf| of size |len|. If
// this returns zero, then the decryption failed.
size_t pairing_auth_safe_decrypted_size(PairingAuthCtx* ctx, const uint8_t* buf, size_t len);

// Decrypts |inbuf| and writes result to |outbuf|. If decryption fails, the return
// will be false, otherwise true.
bool pairing_auth_decrypt(PairingAuthCtx* ctx, const uint8_t* inbuf, size_t inlen, uint8_t* outbuf,
                          size_t* outlen);

}  // extern "C"
