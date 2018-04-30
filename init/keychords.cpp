/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <keychord/keychord.h>

#include "init.h"

namespace android {
namespace init {

static int keychord_fd = -1;
static int keychords;

void add_service_keycodes(Service* svc)
{
    if (!svc->keycodes().empty()) {
        if (keychord_fd < 0) {
            keychord_fd = keychord_initialize(
                [](keychord_epoll_handler_fn fn, int fd, const char*) {
                    register_epoll_handler(fd, fn);
                    return 0;
                },
                [](int fd, const char*) {
                    unregister_epoll_handler(fd);
                    return 0;
                });
        }
        if (keychord_enable(keychord_fd, EV_KEY, svc->keycodes()) >= 0) ++keychords;
    }
}

static void handle_keychord(int id) {
    // Only handle keychords if adb is enabled.
    std::string adb_enabled = android::base::GetProperty("init.svc.adbd", "");
    if (adb_enabled == "running") {
        Service* svc = ServiceList::GetInstance().FindService(id, &Service::keychord_id);
        if (svc) {
            LOG(INFO) << "Starting service '" << svc->name() << "' from keychord " << id;
            if (auto result = svc->Start(); !result) {
                LOG(ERROR) << "Could not start service '" << svc->name() << "' from keychord " << id
                           << ": " << result.error();
            }
        } else {
            LOG(ERROR) << "Service for keychord " << id << " not found";
        }
    } else {
        LOG(WARNING) << "Not starting service for keychord " << id << " because ADB is disabled";
    }
}

void keychord_init() {
    for (const auto& service : ServiceList::GetInstance()) {
        add_service_keycodes(service.get());
    }

    // Nothing to do if no services require keychords.
    if (keychord_fd < 0) return;
    if (keychords == 0) {
        keychord_release(keychord_fd);
        keychord_fd = -1;
        return;
    }

    keychord_register_id_handler(keychord_fd, handle_keychord);
}

}  // namespace init
}  // namespace android
