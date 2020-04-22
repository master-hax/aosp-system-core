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

#include <memory>

#include "tcp_socket.h"
#include "transport.h"

class ClientTcpTransport : public Transport {
  public:
    ClientTcpTransport();
    ~ClientTcpTransport() override = default;

    ssize_t Read(void* data, size_t len) override;
    ssize_t Write(const void* data, size_t len) override;
    int Close() override;
    int Reset() override;

  private:
    void ListenFastbootSocket();

    std::unique_ptr<TcpSocket> service_;
    std::unique_ptr<TcpSocket> socket_;
    uint64_t message_bytes_left_ = 0;
    bool downloading_ = false;

    DISALLOW_COPY_AND_ASSIGN(ClientTcpTransport);
};
