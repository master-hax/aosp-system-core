/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "vndksupport"

#include "linker.h"

#include <android-base/file.h>
#include <android-base/strings.h>
#include <android/dlext.h>
#include <dlfcn.h>
#include <log/log.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <initializer_list>
#include <string>

extern "C" android_namespace_t* android_get_exported_namespace(const char*);

namespace {

struct VendorNamespace {
    android_namespace_t* ptr = nullptr;
    const char* name = nullptr;
};

int IsInVendorProcess() {
    // Special case init
    if (getpid() == 1) {
        return 0;
    }

    std::string argv;
    if (!android::base::ReadFileToString("/proc/self/cmdline", &argv)) {
        // If it fails to read /proc/self/cmdline, assume as vendor process.
        return 1;
    }

    // Check if APEX is in system if cmdline starts with /apex/
    if (android::base::StartsWith(argv, "/apex/")) {
        std::string apex_path = argv.substr(6);
        std::ifstream system_apexes("/linkerconfig/system.apexes.txt", std::ifstream::in);
        if (!system_apexes) {
            ALOGE("IsInVendorProcess : failed to read /linkerconfig/system.apexes.txt");
            return 1;
        }

        std::string system_apex;
        while (std::getline(system_apexes, system_apex)) {
            if (android::base::StartsWith(apex_path, system_apex)) {
                return 0;
            }
        }

        return 1;
    }

    // Read dir - section map from ld.config.txt
    std::ifstream linker_config("/linkerconfig/ld.config.txt", std::ifstream::in);
    if (!linker_config) {
        ALOGE("IsInVendorProcess : failed to read /linkerconfig/ld.config.txt");
        return 1;
    }

    std::string config_line;
    while (std::getline(linker_config, config_line)) {
        size_t found = config_line.find('#');
        config_line = android::base::Trim(config_line.substr(0, found));

        if (config_line.empty()) {
            continue;
        }

        if (config_line[0] == '[') {
            // Section starts. Stop reading ld.config.txt.
            break;
        }

        size_t found_assign = config_line.find('=');

        if (found_assign != std::string::npos) {
            std::string section = android::base::Trim(config_line.substr(0, found_assign));
            std::string path_prefix = android::base::Trim(config_line.substr(found_assign + 1));

            if (android::base::StartsWith(argv, path_prefix)) {
                return (section == "dir.system" || section == "dir.unrestricted") ? 0 : 1;
            }
        }
    }

    // Any of match failed. Assume as vendor process.
    return 1;
}
}  // anonymous namespace

static VendorNamespace get_vendor_namespace() {
    static VendorNamespace result = ([] {
        for (const char* name : {"sphal", "vendor", "default"}) {
            if (android_namespace_t* ns = android_get_exported_namespace(name)) {
                return VendorNamespace{ns, name};
            }
        }
        return VendorNamespace{};
    })();
    return result;
}

int android_is_in_vendor_process() {
    static bool is_in_vendor_process = IsInVendorProcess();
    return is_in_vendor_process;
}

void* android_load_sphal_library(const char* name, int flag) {
    VendorNamespace vendor_namespace = get_vendor_namespace();
    if (vendor_namespace.ptr != nullptr) {
        const android_dlextinfo dlextinfo = {
                .flags = ANDROID_DLEXT_USE_NAMESPACE,
                .library_namespace = vendor_namespace.ptr,
        };
        void* handle = android_dlopen_ext(name, flag, &dlextinfo);
        if (!handle) {
            ALOGE("Could not load %s from %s namespace: %s.", name, vendor_namespace.name,
                  dlerror());
        }
        return handle;
    } else {
        ALOGW("Loading %s from current namespace instead of sphal namespace.", name);
        return dlopen(name, flag);
    }
}

int android_unload_sphal_library(void* handle) {
    return dlclose(handle);
}
