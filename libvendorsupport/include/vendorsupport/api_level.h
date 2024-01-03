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

#pragma once

#include <android/api-level.h>

#define __ANDROID_VENDOR_API_FUTURE__ 1000000

#ifndef __ANDROID_VENDOR_API__
#define __ANDROID_VENDOR_API__ __ANDROID_VENDOR_API_FUTURE__
#endif

#define __ANDROID_VENDOR_API_24Q2__ 202404

#ifdef __cplusplus
extern "C" {
#endif

int vendor_api_level_of(int sdk_api_level);

int sdk_api_level_of(int vendor_api_level);

#ifdef __cplusplus
}
#endif
