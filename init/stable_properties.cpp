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
    enforced_ = android::base::GetBoolProperty("ro.compatible_property.enabled", false);
    if (enforced_) {
        for (const auto* partner_prefix : kPartnerPrefixes) {
            partner_prefixes_.emplace_back(partner_prefix);
        }
        for (const auto* exported_actionable_property : kExportedActionableProperties) {
            exported_actionable_properties_.emplace(exported_actionable_property);
        }
        LoadExtendedActionablePropertyFiles();
    }
}

void StableActionablePropertyManager::LoadExtendedActionableProperties(char* data) {
    char *eol, *sol;

    sol = data;
    while ((eol = strchr(sol, '\n'))) {
        *eol++ = 0;
        std::string line(sol);
        std::string property_name = android::base::Trim(line);
        if (!property_name.empty()) {
            extended_actionable_properties_.emplace(property_name);
        }
        sol = eol;
    }
}

void StableActionablePropertyManager::LoadExtendedActionablePropertyFiles() {
    static const char* extended_actionable_property_files[] = {
        "/vendor/etc/extended_actionable_properties", "/odm/etc/extended_actionable_properties",
    };

    for (const auto* filename : extended_actionable_property_files) {
        auto file_contents = ReadFile(filename);
        if (!file_contents) {
            PLOG(INFO) << "Couldn't load extended actionable property file '" << filename
                       << "': " << file_contents.error();
            continue;
        }

        file_contents->push_back('\n');
        LoadExtendedActionableProperties(file_contents->data());
    }
}

bool StableActionablePropertyManager::IsActionable(const std::string& prop_name) {
    if (!enforced_) {
        return true;
    }

    if (exported_actionable_properties_.find(prop_name) != exported_actionable_properties_.end()) {
        return true;
    }
    if (extended_actionable_properties_.find(prop_name) != extended_actionable_properties_.end()) {
        return true;
    }
    for (const auto& prefix : partner_prefixes_) {
        if (android::base::StartsWith(prop_name, prefix)) {
            return true;
        }
    }
    return false;
}

}  // namespace init
}  // namespace android
