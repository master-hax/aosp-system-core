/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "stable_properties.h"

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>

namespace android {
namespace init {

bool IsActionableProperty(bool execute_in_subcontext, const std::string& prop_name) {
    static bool enabled =
        android::base::GetBoolProperty("ro.actionable_compatible_property.enabled", false);

    if (!execute_in_subcontext || !enabled) {
        return true;
    }

    if (kExportedActionableProperties.count(prop_name) == 1) {
        return true;
    }
    for (const auto& prefix : kPartnerPrefixes) {
        if (android::base::StartsWith(prop_name, prefix)) {
            return true;
        }
    }
    return false;
}

}  // namespace init
}  // namespace android
