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

#include "adb.h"
#include "pairing/pairing.h"
#include "sysdeps.h"
#include "transport.h"

#include <unistd.h>

#include <adbd_wifi.h>

#define DEBUGON 1

static AdbdWifiContext* sWifiCtx;

static bool adbd_wifi_enable_discovery(const uint8_t* ourSPAKE2Key, uint64_t sz) {
    return pair_host(ourSPAKE2Key, sz);
}

static void adbd_wifi_disable_discovery() {
    pair_cancel();
}

static void adbd_wifi_send_pair_request(const uint8_t* pairing_request,
                                        uint64_t sz) {
    pair_host_send_pairing_request(pairing_request,
                                   sz);
}

void adbd_wifi_init(void) {
    AdbdWifiCallbacks cb;
    cb.version = 1;
    cb.callbacks.v1.enable_discovery = adbd_wifi_enable_discovery;
    cb.callbacks.v1.disable_discovery = adbd_wifi_disable_discovery;
    cb.callbacks.v1.send_pairing_request = adbd_wifi_send_pair_request;
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
