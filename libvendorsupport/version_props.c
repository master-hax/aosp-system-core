// Copyright (C) 2024 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "api_level.h"

#include <log/log.h>

int android_get_vendor_api_level_of(int sdk_api_level) {
    if (sdk_api_level < __ANDROID_API_V__) {
        return sdk_api_level;
    }
    // In Android V, vendor API level started with version 202404.
    // The calculation assumes that the SDK api level bumps once a year.
    if (sdk_api_level < __ANDROID_API_FUTURE__) {
        return 202404 + ((sdk_api_level - __ANDROID_API_V__) * 100);
    }
    ALOGE("The SDK version must be less than 10000: %d", sdk_api_level);
    return __INVALID_API_LEVEL;
}

int android_get_sdk_api_level_of(int vendor_api_level) {
    if (vendor_api_level < __ANDROID_API_V__) {
        return vendor_api_level;
    }
    if (vendor_api_level >= 202404 && vendor_api_level < __ANDROID_VENDOR_API_MAX__) {
        return (vendor_api_level - 202404) / 100 + __ANDROID_API_V__;
    }
    ALOGE("Unexpected vendor api level: %d", vendor_api_level);
    return __INVALID_API_LEVEL;
}
