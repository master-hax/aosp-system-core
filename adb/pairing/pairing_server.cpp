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

#include "adb_wifi.h"
#include "sysdeps.h"

static constexpr size_t kMaxConnections = 100;

using DataType = PairingConnection::DataType;

PairingServer::PairingServer(const uint8_t* publicKey,
                             uint64_t sz) {
    mOurKey.assign(publicKey, publicKey + sz);
}

bool PairingServer::listen(std::string* response, int port) {
    std::condition_variable cv;
    std::mutex mutex;
    bool success = false;

    auto callback = [&](bool result) {
        LOG(ERROR) << "receiving PairingServer callback";
        std::unique_lock<std::mutex> lock(mutex);
        success = result;
        cv.notify_all();
    };

    LOG(ERROR) << "PairingServer::listen setting up server";
    unique_fd fd(network_inaddr_any_server(port, SOCK_STREAM, response));
    if (fd.get() == -1) {
        LOG(ERROR) << "PairingServer::listen to create server";
        *response = "failed to create pairing server";
        return false;
    }
    close_on_exec(fd.get());

    std::unique_lock<std::mutex> lock(mutex);
    fdevent_run_on_main_thread([&]() {
        LOG(ERROR) << "PairingServer::listen creating fd event for fd " << fd.get();
        mFdEvent = fdevent_create(fd.release(),
                                   &PairingServer::staticOnFdEvent,
                                   this);
        if (mFdEvent == nullptr) {
            LOG(ERROR) << "PairingServer::listen failed to create fd event";
            *response = "failed to create pairing event";
            callback(false);
            return;
        }
        LOG(ERROR) << "PairingServer::listen successfully created fd event";
        callback(true);
    });

    LOG(ERROR) << "pairing_server::listen waiting for cv";
    cv.wait(lock);
    LOG(ERROR) << "pairing_server::listen triggered on cv";
    if (success) {
        LOG(ERROR) << "PairingServer::listen setting fd event";
        fdevent_set(mFdEvent, FDE_READ);
    }

    return success;
}

void PairingServer::sendPairingRequest(const uint8_t* pairing_request,
                                       uint64_t sz) {
    if (m_pairing_fd_ == -1 ||
        mConnections.find(m_pairing_fd_) == mConnections.end()) {
        // The connection may have been broken.
        LOG(ERROR) << "No clients are currently in the pairing process.";
        m_pairing_fd_ = -1;
        return;
    }
    if (!mConnections[m_pairing_fd_]->sendRawMsg(pairing_request, sz)) {
        LOG(ERROR) << "Unable to send the pairing request packet.";
    }
    LOG(INFO) << "Sent pairing request packet.";
    // Break all pairing connections. When this function gets called, we have
    // already successfully saved a client's public key.
    mConnections.clear();
    m_pairing_fd_ = -1;
}

int PairingServer::getPort() const {
    return adb_socket_get_local_port(mFdEvent->fd);
}

void PairingServer::staticOnFdEvent(int fd, unsigned ev, void* data) {
    PLOG(ERROR) << "PairingServer::staticOnFdEvent";
    if (data == nullptr) {
        LOG(ERROR) << "PairingServer::staticOnFdEvent recieved NULL data";
        return;
    }
    auto server = reinterpret_cast<PairingServer*>(data);
    server->onFdEvent(fd, ev);
}

void PairingServer::onFdEvent(int fd, unsigned ev) {
    if ((ev & FDE_READ) == 0 || fd != mFdEvent->fd.get()) {
        LOG(INFO) << __func__ << ": No reading (ev=" << ev << ", fd=" << fd << ")";
        return;
    }

    LOG(INFO) << __func__ << ": Attempting to adb_socket_accept (fd=" << fd << ")";
    int clientFd = adb_socket_accept(fd, nullptr, nullptr);
    if (clientFd == -1) {
        LOG(WARNING) << __func__ << ": adb_socket_accept failed (fd=" << fd << ")";
        return;
    }
    auto callback = [this, clientFd](bool success) {
        LOG(INFO) << "Client disconnected [fd=" << clientFd << "]";
        if (success) {
            LOG(INFO) << "client succeeded with pairing";
            // One client succeeded, don't accept any more incoming connections.
            fdevent_destroy(mFdEvent);
            mFdEvent = nullptr;
            // Disconnect all connections except for the one we're pairing with.
            // We need to send our pairing request over so we can't break the
            // connection quite yet.
            if (mConnections.find(clientFd) == mConnections.end()) {
                LOG(ERROR) << "Client somehow no longer in the list of connections. Not good...";
                return;
            }
            auto connection = std::move(mConnections[clientFd]);
            mConnections.clear();
            if (m_pairing_fd_ != clientFd) {
                LOG(ERROR) << "fd=" << m_pairing_fd_<< " was in the pairing process, "
                           << "but clientFd=" << clientFd << " is now pairing. "
                           << "Aborting this connection for safety.";
            }
            mConnections[clientFd] = std::move(connection);
        } else {
            // This client failed, disconnect it
            mConnections.erase(clientFd);
            if (clientFd == m_pairing_fd_) {
                m_pairing_fd_ = -1;
            }
        }
    };

    auto connection = std::make_unique<PairingConnection>(callback, processMsg, this);
    if (!connection->start(PairingRole::Server, clientFd)) {
        return;
    }
    connection->sendRawMsg(mOurKey.data(), mOurKey.size());

    mConnections[clientFd] = std::move(connection);

    if (mConnections.size() >= kMaxConnections) {
        // Close the socket to limit the maximum number of concurrent
        // connections. This is to avoid using too much resources.
        fdevent_destroy(mFdEvent);
        mFdEvent = nullptr;
    }
}

bool PairingServer::handleMsg(std::string_view msg,
                              int fd,
                              DataType dataType) {
    // Don't need a lock here because adbd_wifi_pairing_request() will
    // synchronize the requests for us.
    LOG(INFO) << "PairingServer got message";
    switch (dataType) {
        case DataType::PublicKey:
            // PairingServer should not get PublicKey type. the PublicKeyHeader
            // will include this information already.
            return false;
        case DataType::PairingRequest:
            if (m_pairing_fd_ != -1) {
                LOG(ERROR) << "Pairing request process already started by another connection."
                           << " Ignoring this request.";
                return false;
            }
            m_pairing_fd_ = fd;
            LOG(INFO) << "fd=" << m_pairing_fd_ << " entered pairing request process";
            // Send message to system server.
            adbd_wifi_pairing_request(reinterpret_cast<const uint8_t*>(msg.data()),
                                      msg.size());
            break;
    }

    return true;
}

// static
bool PairingServer::processMsg(std::string_view msg,
                               DataType dataType,
                               int fd,
                               void* opaque) {
    auto* ptr = reinterpret_cast<PairingServer*>(opaque);
    return ptr->handleMsg(msg, fd, dataType);
}
