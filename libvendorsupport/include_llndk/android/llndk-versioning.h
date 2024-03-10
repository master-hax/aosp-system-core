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

#include <sys/cdefs.h>

__BEGIN_DECLS

#if defined(__ANDROID_VENDOR__)

// LLNDK (https://source.android.com/docs/core/architecture/vndk/build-system#ll-ndk) is similar to
// NDK, but uses its own versioning of YYYYMM format for vendor builds. The LLNDK symbols are
// enabled when the vendor api level is equal to or newer than the ro.board.api_level.
// Use __INTRODUCED_IN_LLNDK if the symbol is available only to vendor modules as LLNDK.
#define __INTRODUCED_IN_LLNDK(vendor_api_level)                                             \
    _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wgcc-compat\"")   \
            __attribute__((enable_if(                                                       \
                    __ANDROID_VENDOR_API__ >= vendor_api_level,                             \
                    "available in vendor API level " #vendor_api_level " that "             \
                    "is newer than the current vendor API level. Guard the API "            \
                    "call with '#if (__ANDROID_VENDOR_API__ >= " #vendor_api_level ")'."))) \
            _Pragma("clang diagnostic pop")

// If the symbol is available to both NDK and LLNDK use __INTRODUCED_IN_NDK_LLNDK with both api
// levels. Symbols added in Android U or older can use __INTRODUCED_IN in any cases.
#define __INTRODUCED_IN_NDK_LLNDK(sdk_api_level, vendor_api_level) \
    __INTRODUCED_IN_LLNDK(vendor_api_level)

// Use this macro as an `if` statement to call an API that are available to both NDK and LLNDK.
// This returns true for the vendor modules if the vendor_api_level is less than or equal to the
// ro.board.api_level.
#define ANDROID_NDK_LLNDK_AT_LEAST(sdk_api_level, vendor_api_level) \
    constexpr(__ANDROID_VENDOR_API__ >= vendor_api_level)

#else  // __ANDROID_VENDOR__

// __INTRODUCED_IN_LLNDK is for LLNDK only but not for NDK. This is replaced with
// __INTRODUCED_IN(__ANDROID_API_FUTURE__) for non-vendor modules., It leaves a no-op annotation
// for ABI analysis.
#define __INTRODUCED_IN_LLNDK(vendor_api_level)                         \
    __attribute__((annotate("introduced_in_llndk=" #vendor_api_level))) \
    __INTRODUCED_IN(__ANDROID_API_FUTURE__)

// For non-vendor modules, replace __INTRODUCED_IN_NDK_LLNDK with __INTRODUCED_IN. It leaves a no-op
// annotation for ABI analysis.
#define __INTRODUCED_IN_NDK_LLNDK(sdk_api_level, vendor_api_level)      \
    __attribute__((annotate("introduced_in_llndk=" #vendor_api_level))) \
    __INTRODUCED_IN(sdk_api_level)

// For non-vendor modules, it is replaced with __builtin_available(__builtin_available) to guard the
// API for __INTRODUCED_IN.
#define ANDROID_NDK_LLNDK_AT_LEAST(sdk_api_level, vendor_api_level) \
    (__builtin_available(android sdk_api_level, *))

#endif  // __ANDROID_VENDOR__

// Use ANDROID_LLNDK_AT_LEAST to guard the LLNDK only symbols
#define ANDROID_LLNDK_AT_LEAST(vendor_api_level) \
    ANDROID_NDK_LLNDK_AT_LEAST(__ANDROID_API_FUTURE__, vendor_api_level)

__END_DECLS
