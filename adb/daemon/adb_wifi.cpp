/*
 * Copyright (C) 2019 The Android Open Source Project
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

#if !ADB_HOST

#define TRACE_TAG ADB_WIRELESS

#include "adb_wifi.h"

#include <unistd.h>
#include <optional>

#include <adbd_auth.h>

#include "adb.h"
#include "daemon/mdns.h"
#include "sysdeps.h"
#include "transport.h"

namespace {

static AdbdAuthContext* auth_ctx;

static void adb_disconnected(void* unused, atransport* t);
static struct adisconnect adb_disconnect = {adb_disconnected, nullptr};

class TlsServer {
  public:
    explicit TlsServer(int port);
    virtual ~TlsServer();
    bool Start();
    uint16_t port() { return port_; };

  private:
    void OnFdEvent(int fd, unsigned ev);
    static void StaticOnFdEvent(int fd, unsigned ev, void* opaque);

    fdevent* fd_event_ = nullptr;
    uint16_t port_;
};  // TlsServer

TlsServer::TlsServer(int port) : port_(port) {}

TlsServer::~TlsServer() {
    fdevent* fde = fd_event_;
    fdevent_run_on_main_thread([fde]() {
        if (fde != nullptr) {
            fdevent_destroy(fde);
        }
    });
    adbd_auth_wifi_debugging_disconnected(auth_ctx, port_);
}

bool TlsServer::Start() {
    std::condition_variable cv;
    std::mutex mutex;
    std::optional<bool> success;
    auto callback = [&](bool result) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            success = result;
        }
        cv.notify_one();
    };

    std::string err;
    unique_fd fd(network_inaddr_any_server(port_, SOCK_STREAM, &err));
    if (fd.get() == -1) {
        LOG(ERROR) << "Failed to start TLS server [" << err << "]";
        adbd_auth_wifi_debugging_disconnected(auth_ctx, port_);
        return false;
    }
    close_on_exec(fd.get());
    int port = socket_get_local_port(fd.get());
    if (port <= 0 || port > 65535) {
        LOG(ERROR) << "Invalid port for tls server";
        return false;
    }
    port_ = static_cast<uint16_t>(port);
    LOG(INFO) << "adbwifi started on port " << port_;

    std::unique_lock<std::mutex> lock(mutex);
    fdevent_run_on_main_thread([&]() {
        fd_event_ = fdevent_create(fd.release(), &TlsServer::StaticOnFdEvent, this);
        if (fd_event_ == nullptr) {
            LOG(ERROR) << "Failed to create fd event for TlsServer.";
            callback(false);
            return;
        }
        callback(true);
    });

    cv.wait(lock, [&]() { return success.has_value(); });
    if (!*success) {
        LOG(INFO) << "TlsServer fdevent_create failed";
        adbd_auth_wifi_debugging_disconnected(auth_ctx, port_);
        return false;
    }
    fdevent_set(fd_event_, FDE_READ);
    LOG(INFO) << "TlsServer running on port " << port_;
    adbd_auth_wifi_debugging_connected(auth_ctx, port_);

    return *success;
}

// static
void TlsServer::StaticOnFdEvent(int fd, unsigned ev, void* opaque) {
    auto server = reinterpret_cast<TlsServer*>(opaque);
    server->OnFdEvent(fd, ev);
}

void TlsServer::OnFdEvent(int fd, unsigned ev) {
    if ((ev & FDE_READ) == 0 || fd != fd_event_->fd.get()) {
        LOG(INFO) << __func__ << ": No read [ev=" << ev << " fd=" << fd << "]";
        return;
    }

    unique_fd new_fd(adb_socket_accept(fd, nullptr, nullptr));
    if (new_fd >= 0) {
        LOG(INFO) << "New TLS connection [fd=" << new_fd.get() << "]";
        close_on_exec(new_fd.get());
        disable_tcp_nagle(new_fd.get());
        std::string serial = android::base::StringPrintf("host-%d", new_fd.get());
        register_socket_transport(
                std::move(new_fd), std::move(serial), port_, 1,
                [](atransport*) { return ReconnectResult::Abort; }, true);
    }
}

static void adb_disconnected(void* unused, atransport* t) {
    LOG(INFO) << "ADB wifi device disconnected";
    adbd_auth_wifi_device_disconnected(auth_ctx, t->auth_id);
}

TlsServer* sTlsServer = nullptr;

}  // namespace

void adbd_wifi_init(AdbdAuthContext* ctx) {
    auth_ctx = ctx;
}

void adbd_wifi_enable_debugging() {
    if (sTlsServer != nullptr) {
        delete sTlsServer;
    }
    sTlsServer = new TlsServer(0);
    if (!sTlsServer->Start()) {
        LOG(ERROR) << "Failed to start TlsServer";
    }
    // Start mdns connect service for discovery
    register_adb_secure_connect_service(sTlsServer->port());
}

void adbd_wifi_disable_debugging() {
    if (sTlsServer != nullptr) {
        delete sTlsServer;
        sTlsServer = nullptr;
    }
    if (is_adb_secure_connect_service_registered()) {
        unregister_adb_secure_connect_service();
    }
    kick_all_tcp_tls_transports();
}

void adbd_wifi_disconnect_device(const char* public_key, size_t len) {
    // The framework removed the key from its keystore. We need to disconnect all
    // devices using that key. Search by t->auth_key
    std::string_view auth_key(public_key, len);
    kick_all_transports_by_auth_key(auth_key);
}

void adbd_wifi_init(AdbdAuthContext* ctx, AdbdAuthCallbacks* cb) {
    auth_ctx = ctx;
}

void adbd_wifi_secure_connect(atransport* t) {
    t->AddDisconnect(&adb_disconnect);
    handle_online(t);
    send_connect(t);
    LOG(INFO) << __func__ << ": connected " << t->serial;
    t->auth_id = adbd_auth_wifi_device_connected(auth_ctx, t->auth_key.data(), t->auth_key.size());
}

#endif /* !HOST */
