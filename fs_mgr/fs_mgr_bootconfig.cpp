/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/properties.h>

#include "fs_mgr_priv.h"

int fs_mgr_get_boot_config(const char* config, std::string* val) {
    val->clear();

    // first check if we have "ro.boot" property already
    char propbuf[PROPERTY_VALUE_MAX];
    std::string propkey = android::base::StringPrintf("ro.boot.%s", config);
    if (property_get(propkey.c_str(), propbuf, "") > 0) {
        val->append(propbuf);
        return 0;
    }

    // fallback to kernel cmdline if properties may not be ready yet
    std::string cmdline;
    std::string cmdline_config =  android::base::StringPrintf("androidboot.%s", config);
    if (android::base::ReadFileToString("/proc/cmdline", &cmdline)) {
        for (const auto& entry : android::base::Split(android::base::Trim(cmdline), " ")) {
            std::vector<std::string> pieces = android::base::Split(entry, "=");
            if (pieces.size() == 2) {
                if (pieces[0] == cmdline_config) {
                    val->append(pieces[1]);
                    return 0;
                }
            }
        }
    }

    // lastly, check the device tree
    static constexpr char android_dt_dir[] = "/proc/device-tree/firmware/android";
    std::string file_name = android::base::StringPrintf("%s/compatible", android_dt_dir);
    std::string dt_value;
    if (android::base::ReadFileToString(file_name, &dt_value)) {
        if (!dt_value.compare("android,firmware")) {
            LERROR << "Error finding compatible android DT node";
            return -1;
        }

        file_name = android::base::StringPrintf("%s/%s", android_dt_dir, config);
        // DT entries terminate with '\0' but so do the properties
        if (android::base::ReadFileToString(file_name, val)) {
            return 0;
        }

        LERROR << "Error finding '" << config << "' in device tree";
    }

    return -1;
}
