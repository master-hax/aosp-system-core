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

#include "init_kernel.h"

#include <dirent.h>
#include <string.h>

#include <algorithm>
#include <memory>
#include <string>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>

#include "property_service.h"
#include "util.h"

using namespace std::string_literals;

namespace android {
namespace init {

static char qemu[2];

static void import_kernel_nv(const std::string& key, const std::string& value, bool for_emulator) {
    if (key.empty()) return;

    if (for_emulator) {
        // In the emulator, export any kernel option with the "ro.kernel." prefix.
        property_set("ro.kernel." + key, value);
        return;
    }

    if (key == "qemu") {
        strlcpy(qemu, value.c_str(), sizeof(qemu));
        return;
    }

    static constexpr char androidboot[] = "androidboot.";
    if (android::base::StartsWith(key, androidboot)) {
        property_set("ro.boot." + key.substr(strlen(androidboot)), value);
    }
}

static void export_kernel_boot_props() {
    constexpr const char* UNSET = "";
    struct {
        const char* src_prop;
        const char* dst_prop;
        const char* default_value;
    } prop_map[] = {
            {
                    "ro.boot.serialno",
                    "ro.serialno",
                    UNSET,
            },
            {
                    "ro.boot.mode",
                    "ro.bootmode",
                    "unknown",
            },
            {
                    "ro.boot.baseband",
                    "ro.baseband",
                    "unknown",
            },
            {
                    "ro.boot.bootloader",
                    "ro.bootloader",
                    "unknown",
            },
            {
                    "ro.boot.hardware",
                    "ro.hardware",
                    "unknown",
            },
            {
                    "ro.boot.revision",
                    "ro.revision",
                    "0",
            },
    };
    for (const auto& prop : prop_map) {
        std::string value = android::base::GetProperty(prop.src_prop, prop.default_value);
        if (value != UNSET) {
            property_set(prop.dst_prop, value);
        }
    }
}

static void process_kernel_dt() {
    if (!is_android_dt_value_expected("compatible", "android,firmware")) {
        return;
    }

    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(get_android_dt_dir().c_str()), closedir);
    if (!dir) return;

    std::string dt_file;
    struct dirent* dp;
    while ((dp = readdir(dir.get())) != NULL) {
        if (dp->d_type != DT_REG || !strcmp(dp->d_name, "compatible") ||
            !strcmp(dp->d_name, "name")) {
            continue;
        }

        std::string file_name = get_android_dt_dir() + dp->d_name;

        android::base::ReadFileToString(file_name, &dt_file);
        std::replace(dt_file.begin(), dt_file.end(), ',', '.');

        property_set("ro.boot."s + dp->d_name, dt_file);
    }
}

static void process_kernel_cmdline() {
    // The first pass does the common stuff, and finds if we are in qemu.
    // The second pass is only necessary for qemu to export all kernel params
    // as properties.
    import_kernel_cmdline(false, import_kernel_nv);
    if (qemu[0]) import_kernel_cmdline(true, import_kernel_nv);
}

void process_kernel() {
    // If arguments are passed both on the command line and in DT,
    // properties set in DT always have priority over the command-line ones.
    process_kernel_dt();
    process_kernel_cmdline();

    // Propagate the kernel variables to internal variables
    // used by init as well as the current required properties.
    export_kernel_boot_props();
}

}  // namespace init
}  // namespace android
