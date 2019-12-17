/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
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

#include <string_view>
#include <vector>

namespace adb {
namespace ssl {

class TlsConnection {
  public:
    enum class Role {
        Server,
        Client,
    };

    virtual ~TlsConnection() = default;

    // Disables certificate verification. This will allow all connections, as
    // long as the peer provides a certificate. Certificate verification is
    // enabled by default. Must call before |DoHandshake| for it to take effect.
    virtual void EnableCertificateVerification(bool enable) = 0;

    // Adds a trusted certificate to the list for the SSL connection.
    // During the handshake phase, it will check the list of trusted certificates.
    // The connection will fail if the peer's certificate is not in the list. Use
    // |EnableCertificateVerification(false)| to disable certificate
    // verification.
    //
    // Returns true if |cert| was successfully added, false otherwise.
    virtual bool AddTrustedCertificate(std::string_view cert) = 0;

    // Exports a value derived from the master secret used in the TLS
    // connection. This value should be used alongside any PAKE to ensure the
    // peer is the intended peer. |length| is the requested length for the
    // keying material. This is only valid after |DoHandshake| succeeds.
    virtual std::vector<uint8_t> ExportKeyingMaterial(size_t length) = 0;

    // starts the handshake process with the given fd.
    virtual bool DoHandshake(int fd) = 0;

    // Reads |size| bytes and returns the data. The returned data has either
    // size |size| or zero, in which case the read failed.
    virtual std::vector<uint8_t> ReadFully(int size) = 0;

    // Writes |size| bytes. Returns true if all |size| bytes were read.
    // Returns false otherwise.
    virtual bool WriteFully(std::string_view data) = 0;

    // Create a new TlsConnection instance. |cert| and |priv_key| cannot be
    // empty.
    static std::unique_ptr<TlsConnection> Create(Role role, std::string_view cert,
                                                 std::string_view priv_key);

  protected:
    TlsConnection() = default;
};  // TlsConnection

}  // namespace ssl
}  // namespace adb
