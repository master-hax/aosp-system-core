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

#include "adb/pairing/pairing_header.h"

extern "C" {

struct PairingConnectionCtx;
typedef void (*pairing_result_cb)(const PeerInfo*, int, void*);

// Starts the pairing connection on a separate thread.
// Upon completion, if the pairing was successful,
// |cb| will be called with the peer information and certificate.
// Otherwise, |cb| will be called with empty data. |fd| should already
// be opened. PairingConnectionCtx will take ownership of the |fd|.
//
// Pairing is successful if both server/client uses the same non-empty
// |pswd|, and they are able to exchange the information. |pswd| and
// |certificate| must be non-empty. start() can only be called once in the
// lifetime of this object.
//
// Returns true if the thread was successfully started, false otherwise.
bool pairing_connection_start(PairingConnectionCtx* ctx, int fd, pairing_result_cb cb,
                              void* opaque);

// Creates a new PairingConnectionCtx instance as the client. May return null if unable
// to create an instance. |pswd|, |certificate|, |priv_key|, and |peer_info|
// cannot be null.
PairingConnectionCtx* pairing_connection_client_new(const uint8_t* pswd, size_t pswd_len,
                                                    const PeerInfo& peer_info,
                                                    const uint8_t* x509_cert_pem, size_t x509_size,
                                                    const uint8_t* priv_key_pem, size_t priv_size);

// Creates a new PairingConnectionCtx instance as the client. May return null if unable
// to create an instance. |pswd|, |certificate|, |priv_key|, and |peer_info|
// cannot be null.
PairingConnectionCtx* pairing_connection_server_new(const uint8_t* pswd, size_t pswd_len,
                                                    const PeerInfo& peer_info,
                                                    const uint8_t* x509_cert_pem, size_t x509_size,
                                                    const uint8_t* priv_key_pem, size_t priv_size);

void pairing_connection_destroy(PairingConnectionCtx* ctx);

}  // extern "C"
