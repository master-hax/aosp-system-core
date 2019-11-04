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

#include "adb.h"
#include "daemon/mdns.h"
#include "pairing/pairing.h"
#include "sysdeps.h"
#include "transport.h"

#include <unistd.h>

#include <adbd_wifi.h>

#define DEBUGON 1

namespace {

static AdbdWifiContext* sWifiCtx;

class TlsServer {
public:
    explicit TlsServer(int port);
    virtual ~TlsServer();
    bool start();

private:
    void onFdEvent(int fd, unsigned ev);
    static void staticOnFdEvent(int fd, unsigned ev, void* opaque);

    fdevent* mFdEvent = nullptr;
    int port_;
};  // TlsServer

TlsServer::TlsServer(int port) : port_(port) { }

TlsServer::~TlsServer() {
}

bool TlsServer::start() {
    LOG(INFO) << "Starting TLS server";
    std::condition_variable cv;
    std::mutex mutex;
    bool success = false;
    auto callback = [&](bool result) {
        std::unique_lock<std::mutex> lock(mutex);
        success = result;
        cv.notify_all();
    };

    std::string err;
    unique_fd fd(network_inaddr_any_server(port_, SOCK_STREAM, &err));
    if (fd.get() == -1) {
        LOG(ERROR) << "Failed to start TLS server [" << err << "]";
        callback(false);
        return false;
    }
    close_on_exec(fd.get());

    std::unique_lock<std::mutex> lock(mutex);
    fdevent_run_on_main_thread([&]() {
        mFdEvent = fdevent_create(fd.release(),
                                  &TlsServer::staticOnFdEvent,
                                  this);
        if (mFdEvent == nullptr) {
            LOG(ERROR) << "Failed to create fd event for TlsServer.";
            callback(false);
            return;
        }
        callback(true);
    });

    LOG(INFO) << "Waiting for TlsServer fd event creation...";
    cv.wait(lock);
    if (!success) {
        LOG(INFO) << "TlsServer fdevent_create failed";
        return false;
    }
    fdevent_set(mFdEvent, FDE_READ);

    return success;
}

// static
void TlsServer::staticOnFdEvent(int fd, unsigned ev, void* opaque) {
    auto server = reinterpret_cast<TlsServer*>(opaque);
    server->onFdEvent(fd, ev);
}

void TlsServer::onFdEvent(int fd, unsigned ev) {
    if ((ev & FDE_READ) == 0 || fd != mFdEvent->fd.get()) {
        LOG(INFO) << __func__ << ": No read [ev=" << ev << " fd=" << fd << "]";
        return;
    }

    unique_fd new_fd(adb_socket_accept(fd, nullptr, nullptr));
    if (new_fd >= 0) {
        LOG(INFO) << "New TLS connection [fd=" << new_fd.get() << "]";
        close_on_exec(new_fd.get());
        disable_tcp_nagle(new_fd.get());
        std::string serial = android::base::StringPrintf("host-%d", new_fd.get());
        register_socket_transport(std::move(new_fd), std::move(serial), port_, 1,
                                  [](atransport*) { return ReconnectResult::Abort; });
    }
}

TlsServer* sTlsServer = nullptr;

}  // namespace

static bool adbd_wifi_enable_discovery(const uint8_t* ourSPAKE2Key, uint64_t sz) {
    register_adb_secure_pairing_service(ADB_WIFI_PAIRING_PORT);
    return pair_host(ourSPAKE2Key, sz);
}

static void adbd_wifi_disable_discovery() {
    unregister_adb_secure_pairing_service();
    pair_cancel();
}

static void adbd_wifi_send_pair_request(const uint8_t* pairing_request,
                                        uint64_t sz) {
    pair_host_send_pairing_request(pairing_request,
                                   sz);
}

static void adbd_wifi_framework_connected() {
    if (sTlsServer != nullptr) {
        delete sTlsServer;
    }
    sTlsServer = new TlsServer(ADB_WIFI_CONNECT_PORT);
    if (!sTlsServer->start()) {
        LOG(ERROR) << "Failed to start TlsServer";
    }
}

static void adbd_wifi_framework_disconnected() {
    if (sTlsServer != nullptr) {
        delete sTlsServer;
        sTlsServer = nullptr;
    }
    if (is_adb_secure_pairing_service_registered()) {
        unregister_adb_secure_pairing_service();
    }
    if (is_adb_secure_connect_service_registered()) {
        unregister_adb_secure_connect_service();
    }
}

static void adbd_wifi_teardown() {
    if (sTlsServer != nullptr) {
        delete sTlsServer;
    }
}

void adbd_wifi_init(void) {
    atexit(adbd_wifi_teardown);
    AdbdWifiCallbacks cb;
    cb.version = 1;
    cb.callbacks.v1.enable_discovery = adbd_wifi_enable_discovery;
    cb.callbacks.v1.disable_discovery = adbd_wifi_disable_discovery;
    cb.callbacks.v1.send_pairing_request = adbd_wifi_send_pair_request;
    cb.callbacks.v1.on_framework_connected = adbd_wifi_framework_connected;
    cb.callbacks.v1.on_framework_disconnected = adbd_wifi_framework_disconnected;

    sWifiCtx = adbd_wifi_new(&cb);

    std::thread([]() {
        adb_thread_setname("adbd wifi");
        adbd_wifi_run(sWifiCtx);
    }).detach();
}

static void __attribute__((unused)) adb_wifi_disconnected(void* unused, atransport* t)  {
    if (DEBUGON) LOG(INFO) << "ADB wifi disconnect";
    adbd_wifi_notify_disconnect(sWifiCtx, t->auth_id);
}

void adbd_wifi_pairing_request(const uint8_t* public_key,
                               uint64_t size_bytes) {
    adbd_wifi_pairing_request(sWifiCtx,
                              public_key,
                              size_bytes);
}

#endif /* !HOST */
