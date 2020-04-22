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

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <android-base/macros.h>
#include <cutils/sockets.h>

class TcpSocket {
  public:
    // Creates a new server bound to |port|.
    static std::unique_ptr<TcpSocket> NewServer(int port);

    // Destructor closes the socket if it's open.
    virtual ~TcpSocket();

    // Sends |length| bytes of |data|. This will continue trying to send until all bytes are
    // transmitted. Returns true on success.
    bool Send(const void* data, size_t length);

    // Sends |buffers| using multi-buffer write, which can be significantly faster than making
    // multiple calls. This will continue sending until all buffers are fully transmitted. Returns
    // true on success.
    bool Send(std::vector<cutils_socket_buffer_t> buffers);

    // Waits up to |timeout_ms| to receive up to |length| bytes of data. |timout_ms| of 0 will
    // block forever. Returns the number of bytes received or -1 on error or timeout.
    ssize_t Receive(void* data, size_t length, int timeout_ms);

    // Calls Receive() until exactly |length| bytes have been received or an error occurs.
    ssize_t ReceiveAll(void* data, size_t length, int timeout_ms);

    // Closes the socket. Returns 0 on success, -1 on error.
    int Close();

    // Accepts an incoming TCP connection. Returns a new TcpSocket connected to the client on
    // success, nullptr on failure.
    std::unique_ptr<TcpSocket> Accept();

  protected:
    // Protected constructor to force factory function use.
    explicit TcpSocket(cutils_socket_t sock);
    cutils_socket_t sock_ = INVALID_SOCKET;

  private:
    DISALLOW_COPY_AND_ASSIGN(TcpSocket);
};
