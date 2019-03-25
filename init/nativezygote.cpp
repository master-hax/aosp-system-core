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

#include <android/dlext.h>
#include <dlfcn.h>

#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>

#include "nativezygote_server.h"

void PreloadLibraries() {
    std::vector<std::string> libraries =
            android::base::Split(android::base::GetProperty("ro.nativezygote.preload", ""), ":");
    for (const std::string& lib : libraries) {
        constexpr android_dlextinfo extinfo = {
                .flags = ANDROID_DLEXT_PRELOAD,
        };
        if (android_dlopen_ext(lib.c_str(), RTLD_LOCAL, &extinfo)) {
            LOG(INFO) << "Preloaded library " << lib;
        } else {
            LOG(ERROR) << "Failed to preload library " << lib;
        }
    }
}

int main() {
    LOG(INFO) << "Native zygote starting";

    const char* socket_name = getenv("NATIVEZYGOTE_SOCKET");
    if (!socket_name) {
        LOG(FATAL) << "Environment variable NATIVEZYGOTE_SOCKET not set";
    }

    PreloadLibraries();

    android::init::NativeZygoteServer server(socket_name);
    server.MainLoop();

    return 0;
}
