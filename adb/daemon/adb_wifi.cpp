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
#include "sysdeps.h"
#include "transport.h"

#include <unistd.h>

#include <adbd_wifi.h>

#define DEBUGON 1

static AdbdWifiContext* sWifiCtx;

static bool adbd_wifi_discovery_enable(bool enable) {
    if (enable) {
        return pair_host();
    } else {
        pair_cancel();
        return true;
    }
}

void adbd_wifi_init(void) {
    AdbdWifiCallbacks cb;
    cb.version = 1;
    cb.callbacks.v1.set_discovery_enabled = adbd_wifi_disable_discovery;
//    cb.callbacks.v1.device_authorized = ;
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

#endif /* !HOST */
