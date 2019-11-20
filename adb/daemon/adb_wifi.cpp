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
#include "sysdeps.h"
#include "transport.h"

#include <unistd.h>

#include <adbd_wifi.h>

#define DEBUGON 1

namespace {

static AdbdWifiContext* sWifiCtx;

static void adb_disconnected(void* unused, atransport* t);
static struct adisconnect adb_disconnect = {adb_disconnected, nullptr};

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
    fdevent* fde = mFdEvent;
    fdevent_run_on_main_thread([fde]() {
        if (fde != nullptr) {
            fdevent_destroy(fde);
        }
    });
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

static void adb_disconnected(void* unused, atransport* t) {
    LOG(INFO) << "ADB wifi device disconnected";
    adbd_wifi_notify_disconnected(sWifiCtx, t->auth_id);
}

TlsServer* sTlsServer = nullptr;

}  // namespace

void adbdwifi_cloexec_auth_socket() {
    int fd = android_get_control_socket("adbdwifi");
    if (fd == -1) {
        PLOG(ERROR) << "Failed to get adbd socket";
        return;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static void adbd_wifi_framework_connected() {
    if (sTlsServer != nullptr) {
        delete sTlsServer;
    }
    sTlsServer = new TlsServer(ADB_WIFI_CONNECT_PORT);
    if (!sTlsServer->start()) {
        LOG(ERROR) << "Failed to start TlsServer";
    }
    // Start mdns connect service for discovery
    register_adb_secure_connect_service(ADB_WIFI_CONNECT_PORT);
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
    LOG(INFO) << "Kicking all secure wifi transports";
    kick_all_secure_wifi_transports();
}

static void adbd_wifi_device_unpaired(const char* guid, size_t len) {
    // The device's certificates have already been removed from the keystore. We
    // just need to disconnect the device if it is currently connected.
    auto* t = find_secure_wifi_transport_by_guid(guid);
    if (t != nullptr) {
        kick_transport(t);
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
    cb.callbacks.v1.on_framework_connected = adbd_wifi_framework_connected;
    cb.callbacks.v1.on_framework_disconnected = adbd_wifi_framework_disconnected;
    cb.callbacks.v1.on_device_unpaired = adbd_wifi_device_unpaired;

    sWifiCtx = adbd_wifi_new(&cb);

    std::thread([]() {
        adb_thread_setname("adbd wifi");
        adbd_wifi_run(sWifiCtx);
    }).detach();
}

void adbd_wifi_secure_connect(atransport* t) {
    t->AddDisconnect(&adb_disconnect);
    handle_online(t);
    send_connect(t);
    LOG(INFO) << __func__ << ": connected guid=" << t->serial;
    t->auth_id = adbd_wifi_notify_connected(sWifiCtx, t->serial.c_str(), t->serial.length());
}
#endif /* !HOST */
