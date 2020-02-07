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
//
// @param pswd the shared secret the server and client use to authenticate each
//             other. Cannot be null or empty.
// @param len the length of the pswd.
// @return a new PairingAuthCtx server instance. Caller is responsible for
//         destroying the context via #pairing_auth_destroy.
PairingAuthCtx* pairing_auth_server_new(const uint8_t* pswd, size_t len);

// Creates a new PairingAuthCtx instance as the client.
//
// @param pswd the shared secret the server and client use to authenticate each
//             other. Cannot be null or empty.
// @param len the length of the pswd.
// @return a new PairingAuthCtx server instance. Caller is responsible for
//         destroying the context via #pairing_auth_destroy.
PairingAuthCtx* pairing_auth_client_new(const uint8_t* pswd, size_t len);

// Destroys the PairingAuthCtx.
//
// @param ctx the PairingAuthCtx instance to destroy.
void pairing_auth_destroy(PairingAuthCtx* ctx);

// Returns the exact size of the SPAKE2 msg.
//
// Use this size as the buffer size when retrieving the message via
// #pairing_auth_get_msg.
//
// @param ctx the PairingAuthCtx instance.
// @return the size of the SPAKE2 message.
size_t pairing_auth_msg_size(PairingAuthCtx* ctx);

// Writes the message to exchange with the other party to |out_buf|.
//
// This is guaranteed to have a valid message if PairingAuthCtx is valid. Use
// #pairing_auth_msg_size to get the size the |out_buf| should be.
//
// @param ctx the PairingAuthCtx instance.
// @param out_buf the buffer the message is written to. The buffer is assumed to
//                be have at least #pairing_auth_msg_size size.
void pairing_auth_get_msg(PairingAuthCtx* ctx, uint8_t* out_buf);

// Processes the peer's |their_msg| and attempts to initialize the cipher for
// encryption.
//
// You can only call this method ONCE with a non-empty |msg|, regardless of success
// or failure. On success, you can use the #pairing_auth_decrypt and #pairing_auth_encrypt
// methods to exchange any further information securely. On failure, this
// PairingAuthCtx instance has no more purpose and should be destroyed.
//
// @param ctx the PairingAuthCtx instance.
// @param their_msg the peer's SPAKE2 msg. See #pairing_auth_get_msg.
// @param msg_len the length of their_msg.
// @return true iff the client and server used the same password when creating
//         the PairingAuthCtx. See
//         https://commondatastorage.googleapis.com/chromium-boringssl-docs/curve25519.h.html#SPAKE2
//         for more details on the SPAKE2 protocol.
bool pairing_auth_init_cipher(PairingAuthCtx* ctx, const uint8_t* their_msg, size_t msg_len);

// Returns a safe buffer size for encrypting data of a certain size.
//
// @param ctx the PairingAuthCtx instance.
// @param len the size of the message wanting to encrypt.
// @return the minimum buffer size to hold an encrypted message of size len. See
// #pairing_auth_encrypt for usage.
size_t pairing_auth_safe_encrypted_size(PairingAuthCtx* ctx, size_t len);

// Encrypts input data and writes the encrypted data into a user-provided buffer.
//
// @param ctx the PairingAuthCtx instance.
// @param inbuf the buffer containing the data to encrypt.
// @param inlen the size of inbuf.
// @param outbuf the buffer to write the encrypted data to.
// @param outlen the size of outbuf. See #pairing_auth_safe_encrypted_size.
// @return true if all the data was encrypted and written to outbuf, false
//         otherwise.
bool pairing_auth_encrypt(PairingAuthCtx* ctx, const uint8_t* inbuf, size_t inlen, uint8_t* outbuf,
                          size_t* outlen);

// Returns a safe buffer size for decrypting data of a certain size.
//
// @param ctx the PairingAuthCtx instance.
// @param buf the buffer containing the encrypted data.
// @param len the size of the buf.
// @return the minimum buffer size to hold a decrypted message of size len. See
//         #pairing_auth_decrypt for usage.
size_t pairing_auth_safe_decrypted_size(PairingAuthCtx* ctx, const uint8_t* buf, size_t len);

// Decrypts input data and writes the decrypted data into a user-provided buffer.
//
// @param ctx the PairingAuthCtx instance.
// @param inbuf the buffer containing the data to decrypt.
// @param inlen the size of inbuf.
// @param outbuf the buffer to write the decrypted data to.
// @param outlen the size of outbuf. See #pairing_auth_safe_decrypted_size.
// @return true if all the data was decrypted and written to outbuf, false
//         otherwise.
bool pairing_auth_decrypt(PairingAuthCtx* ctx, const uint8_t* inbuf, size_t inlen, uint8_t* outbuf,
                          size_t* outlen);

}  // extern "C"
