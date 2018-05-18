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

#include <set>
#include <string>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>

#include "keychords.h"
#include "service.h"

namespace android {
namespace init {

namespace {

std::string format(const std::set<int>& keycodes) {
    char c = '[';
    std::string ret;
    for (auto& code : keycodes) {
        ret += android::base::StringPrintf("%c%d", c, code);
        c = '+';
    }
    return ret + ']';
}

}  // namespace

void HandleKeychord(const std::set<int>& keycodes) {
    // Only handle keychords if adb is enabled.
    std::string adb_enabled = android::base::GetProperty("init.svc.adbd", "");
    if (adb_enabled != "running") {
        LOG(WARNING) << "Not starting service for keychord " << format(keycodes)
                     << " because ADB is disabled";
        return;
    }

    bool found = false;
    for (const auto& service : ServiceList::GetInstance()) {
        auto svc = service.get();
        if (svc->keycodes() == keycodes) {
            LOG(INFO) << "Starting service '" << svc->name() << "' from keychord "
                      << format(keycodes);
            if (auto result = svc->Start(); !result) {
                LOG(ERROR) << "Could not start service '" << svc->name() << "' from keychord "
                           << format(keycodes) << ": " << result.error();
            }
        }
    }
    if (!found) LOG(ERROR) << "Service for keychord " << format(keycodes) << " not found";
}

}  // namespace init
}  // namespace android
