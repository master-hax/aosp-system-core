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

#include "tcp_socket.h"

#include <android-base/errors.h>
#include <android-base/stringprintf.h>

TcpSocket::TcpSocket(cutils_socket_t sock) : sock_(sock) {}

TcpSocket::~TcpSocket() {
    Close();
}

int TcpSocket::Close() {
    int ret = 0;

    if (sock_ != INVALID_SOCKET) {
        ret = socket_close(sock_);
        sock_ = INVALID_SOCKET;
    }

    return ret;
}

ssize_t TcpSocket::ReceiveAll(void* data, size_t length, int timeout_ms) {
    size_t total = 0;

    while (total < length) {
        ssize_t bytes = Receive(reinterpret_cast<char*>(data) + total, length - total, timeout_ms);
        if (bytes <= 0) {
            return -1;
        }
        total += bytes;
    }

    return total;
}

bool TcpSocket::Send(const void* data, size_t length) {
    while (length > 0) {
        ssize_t sent =
                TEMP_FAILURE_RETRY(send(sock_, reinterpret_cast<const char*>(data), length, 0));
        if (sent == -1) {
            return false;
        }
        length -= sent;
    }

    return true;
}

bool TcpSocket::Send(std::vector<cutils_socket_buffer_t> buffers) {
    while (!buffers.empty()) {
        ssize_t sent =
                TEMP_FAILURE_RETRY(socket_send_buffers(sock_, buffers.data(), buffers.size()));
        if (sent == -1) {
            return false;
        }

        // Adjust the buffers to skip past the bytes we've just sent.
        auto iter = buffers.begin();
        while (sent > 0) {
            if (iter->length > static_cast<size_t>(sent)) {
                // Incomplete buffer write; adjust the buffer to point to the next byte to send.
                iter->length -= sent;
                iter->data = reinterpret_cast<const char*>(iter->data) + sent;
                break;
            }

            // Complete buffer write; move on to the next buffer.
            sent -= iter->length;
            ++iter;
        }

        // Shortcut the common case: we've written everything remaining.
        if (iter == buffers.end()) {
            break;
        }
        buffers.erase(buffers.begin(), iter);
    }

    return true;
}

ssize_t TcpSocket::Receive(void* data, size_t length, int timeout_ms) {
    if (timeout_ms > 0) {
        timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    }

    return TEMP_FAILURE_RETRY(recv(sock_, reinterpret_cast<char*>(data), length, 0));
}

std::unique_ptr<TcpSocket> TcpSocket::Accept() {
    cutils_socket_t handler = accept(sock_, nullptr, nullptr);
    if (handler == INVALID_SOCKET) {
        return nullptr;
    }
    return std::unique_ptr<TcpSocket>(new TcpSocket(handler));
}

std::unique_ptr<TcpSocket> TcpSocket::NewServer(int port) {
    cutils_socket_t sock = socket_inaddr_any_server(port, SOCK_STREAM);
    if (sock != INVALID_SOCKET) {
        return std::unique_ptr<TcpSocket>(new TcpSocket(sock));
    }

    return nullptr;
}
