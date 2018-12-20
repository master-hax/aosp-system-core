/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
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

#include "pairing_server.h"

#include <android-base/logging.h>

#include "sysdeps.h"

static constexpr size_t kMaxConnections = 100;

PairingServer::PairingServer(const std::string& password,
                             ResultCallback callback)
    : password_(password), callback_(callback) {
}

bool PairingServer::listen(std::string* response, int port) {
    LOG(ERROR) << "PairingServer::listen setting up server";
    unique_fd fd(network_inaddr_any_server(port, SOCK_STREAM, response));
    if (fd.get() == -1) {
        LOG(ERROR) << "PairingServer::listen to create server";
        *response = "failed to create pairing server";
        return false;
    }
    close_on_exec(fd.get());
    LOG(ERROR) << "PairingServer::listen creating fd event for fd " << fd.get();
    fdevent_ = fdevent_create(fd.release(),
                               &PairingServer::staticOnFdEvent,
                               this);
    if (fdevent_ == nullptr) {
        LOG(ERROR) << "PairingServer::listen failed to create fd event";
        *response = "failed to create pairing event";
        return false;
    }
    LOG(ERROR) << "PairingServer::listen setting fd event";
    fdevent_set(fdevent_, FDE_READ);
    return true;
}

int PairingServer::getPort() const {
    return adb_socket_get_local_port(fdevent_->fd);
}

void PairingServer::staticOnFdEvent(int fd, unsigned ev, void* data) {
    LOG(ERROR) << "PairingServer::staticOnFdEvent";
    if (data == nullptr) {
        LOG(ERROR) << "PairingServer::staticOnFdEvent recieved NULL data";
        return;
    }
    auto server = reinterpret_cast<PairingServer*>(data);
    server->onFdEvent(fd, ev);
}

void PairingServer::onConnectionCallback(bool success) {
}

void PairingServer::onFdEvent(int fd, unsigned ev) {
    if ((ev & FDE_READ) == 0 || fd != fdevent_->fd) {
        return;
    }

    int clientFd = adb_socket_accept(fd, nullptr, nullptr);
    if (clientFd == -1) {
        // Failed
        return;
    }
    auto callback = [this, clientFd](bool success) {
        if (success) {
            // One client succeeded, don't accept any more incoming connections
            fdevent_destroy(fdevent_);
            fdevent_ = nullptr;
            callback_(true);
        } else {
            // This client failed, disconnect it
            connections_.erase(clientFd);
        }
    };

    auto connection = std::make_unique<PairingConnection>(callback);
    if (!connection->start(PairingConnection::Mode::Server,
                          clientFd,
                          password_)) {
        return;
    }

    connections_[clientFd] = std::move(connection);

    if (connections_.size() >= kMaxConnections) {
        // Close the socket to limit the maximum number of concurrent
        // connections. This is to avoid using too much resources.
        fdevent_destroy(fdevent_);
        fdevent_ = nullptr;
    }
}

