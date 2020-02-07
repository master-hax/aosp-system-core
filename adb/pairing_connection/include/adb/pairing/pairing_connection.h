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

// These APIs are for the Adb pairing protocol. This protocol requires both
// sides to possess a shared secret to authenticate each other. The connection
// is over TLS, and requires that both the client and server have a valid
// certificate.
//
// This protocol is one-to-one, i.e., one PairingConnectionCtx server instance
// interacts with only one PairingConnectionCtx client instance. In other words,
// every new client instance must be bound to a new server instance.
//
// If both sides have authenticated, they will exchange their peer information
// (see #PeerInfo).
extern "C" {

struct PairingConnectionCtx;
typedef void (*pairing_result_cb)(const PeerInfo*, int, void*);

// Starts the pairing connection on a separate thread.
//
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
// @param ctx the PairingConnectionCtx instance.
// @param fd the fd connecting the peers. This will take ownership of fd.
// @param cb the user-provided callback that is called with the result of the
//        pairing.
// @param opaque opaque userdata.
// @return true if the thread was successfully started, false otherwise. To stop
//         the connection process, destroy the instance (see
//         #pairing_connection_destroy). If the PairingConnectionCtx is
//         destroyed while still in the pairing process, you will still receive
//         a call to cb.
bool pairing_connection_start(PairingConnectionCtx* ctx, int fd, pairing_result_cb cb,
                              void* opaque);

// Creates a new PairingConnectionCtx instance as the client.
//
// @param pswd the password to authenticate both peers. Cannot be empty.
// @param pswd_len the length of pswd.
// @param peer_info the PeerInfo struct that is exchanged between peers if the
//                  pairing was successful.
// @param x509_cert_pem the X.509 certificate in PEM format. Cannot be empty.
// @param x509_size the size of x509_cert_pem.
// @param priv_key_pem the private key corresponding to the given X.509
//                     certificate, in PEM format. Cannot be empty.
// @param priv_size the size of priv_key_pem.
// @return a new PairingConnectionCtx client instance. The caller is responsible
//         for destroying the context via #pairing_connection_destroy.
PairingConnectionCtx* pairing_connection_client_new(const uint8_t* pswd, size_t pswd_len,
                                                    const PeerInfo& peer_info,
                                                    const uint8_t* x509_cert_pem, size_t x509_size,
                                                    const uint8_t* priv_key_pem, size_t priv_size);

// Creates a new PairingConnectionCtx instance as the server.
//
// @param pswd the password to authenticate both peers. Cannot be empty.
// @param pswd_len the length of pswd.
// @param peer_info the PeerInfo struct that is exchanged between peers if the
//                  pairing was successful.
// @param x509_cert_pem the X.509 certificate in PEM format. Cannot be empty.
// @param x509_size the size of x509_cert_pem.
// @param priv_key_pem the private key corresponding to the given X.509
//                     certificate, in PEM format. Cannot be empty.
// @param priv_size the size of priv_key_pem.
// @return a new PairingConnectionCtx server instance. The caller is responsible
//         for destroying the context via #pairing_connection_destroy.
PairingConnectionCtx* pairing_connection_server_new(const uint8_t* pswd, size_t pswd_len,
                                                    const PeerInfo& peer_info,
                                                    const uint8_t* x509_cert_pem, size_t x509_size,
                                                    const uint8_t* priv_key_pem, size_t priv_size);

// Destroys the PairingConnectionCtx instance.
//
// It is safe to destroy the instance at any point in the pairing process.
//
// @param ctx the PairingConnectionCtx instance to destroy.
void pairing_connection_destroy(PairingConnectionCtx* ctx);

}  // extern "C"
