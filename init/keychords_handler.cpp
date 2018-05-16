/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <string>

#include <android-base/logging.h>
#include <android-base/properties.h>

#include "keychords.h"
#include "service.h"

namespace android {
namespace init {

void HandleKeychord(int id) {
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

}  // namespace init
}  // namespace android
