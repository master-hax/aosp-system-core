/*
 * Copyright (C) 2021 The Android Open Source Project
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

#pragma once

#include "Errors.h"

// It would have been better if this file (ErrorsMacros.h) is entirely in utils/Errors.h. However
// that is infeasible as some (actually many) are using utils/Errors.h via the implicit include path
// `system/core/include` [1].  Since such users are not guaranteed to specify the dependency to
// libbase_headers, the following headers from libbase_headers can't be found.
// [1] build/soong/cc/config/global.go#commonGlobalIncludes
#include <android-base/errors.h>
#include <android-base/result.h>

namespace android {
namespace base {

struct StatusPrinter {
    static std::string print(const status_t& s) { return statusToString(s); }
};

// Specialization of android::base::OkOrFail<V> for V = status_t. See android-base/errors.h
// for the contract.
template <>
struct OkOrFail<status_t> {
    static bool is_ok(const status_t& s) { return s == OK; }
    static status_t unwrap(status_t&& s) { return s; }

    OkOrFail(status_t&& s) : val_(s) {}
    status_t val_;

    operator status_t() const { return val_; }
    template <typename T>
    operator Result<T, status_t>() const {
        return Error<status_t, StatusPrinter>(val_);
    }

    std::string error_message() const { return statusToString(val_); }
};

}  // namespace base
}  // namespace android
