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

#include "util.h"

namespace android {
namespace init {

StableActionablePropertyManager& StableActionablePropertyManager::GetInstance() {
    static StableActionablePropertyManager instance;
    return instance;
}

StableActionablePropertyManager::StableActionablePropertyManager() {
    enabled_ = android::base::GetBoolProperty("ro.compatible_property.enabled", false);
    if (enabled_) {
        for (const auto* exported_actionable_property : kExportedActionableProperties) {
            exported_actionable_properties_.emplace(exported_actionable_property);
        }
        LoadExtendedActionablePropertyFiles();
    }
}

void StableActionablePropertyManager::LoadExtendedActionableProperties(const std::string& data) {
    for (const auto& line : android::base::Split(data, "\n")) {
        std::string property_name = android::base::Trim(line);
        if (!property_name.empty()) {
            extended_actionable_properties_.emplace(property_name);
        }
    }
}

void StableActionablePropertyManager::LoadExtendedActionablePropertyFiles() {
    auto file_contents = ReadFile("/vendor/etc/vendor_actionable_property_exceptions");
    if (!file_contents) {
        PLOG(INFO) << "Couldn't load exceptional vendor actionable property file"
                   << "'/vendor/etc/vendor_actionable_property_exceptions': "
                   << file_contents.error();
        return;
    }

    file_contents->push_back('\n');
    LoadExtendedActionableProperties(*file_contents);
}

bool StableActionablePropertyManager::IsActionable(const std::string& prop_name) {
    if (!enabled_) {
        return true;
    }

    if (exported_actionable_properties_.find(prop_name) != exported_actionable_properties_.end()) {
        return true;
    }
    if (extended_actionable_properties_.find(prop_name) != extended_actionable_properties_.end()) {
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
