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

#pragma once

#include <errno.h>
#include <stdint.h>

#include <string>

namespace android::fiemap {

// Represent error status of libfiemap classes.
class FiemapStatus {
  public:
    enum class ErrorCode : int32_t {
        SUCCESS = 0,
        // Generic non-recoverable failure.
        ERROR,
        // Not enough space
        NO_SPACE,
    };

    // Create from a given errno (specified in errno,h)
    static inline FiemapStatus FromErrno(int error_num) {
        return FiemapStatus(ErrorCodeFromErrno(error_num));
    }

    // Generic error.
    static inline FiemapStatus Error() { return FiemapStatus(ErrorCode::ERROR); }

    // Success.
    static inline FiemapStatus Ok() { return FiemapStatus(ErrorCode::SUCCESS); }

    inline ErrorCode error_code() const { return error_code_; }
    inline bool is_ok() const { return error_code() == ErrorCode::SUCCESS; }
    inline operator bool() const { return is_ok(); }

    // For logging and debugging only.
    inline std::string string() const;

  private:
    ErrorCode error_code_;

    inline FiemapStatus(ErrorCode code) : error_code_(code) {}
    static inline ErrorCode ErrorCodeFromErrno(int error_num);
};

std::string FiemapStatus::string() const {
    switch (error_code()) {
        case FiemapStatus::ErrorCode::SUCCESS:
            return "Success";
        case FiemapStatus::ErrorCode::ERROR:
            return "Error";
        case FiemapStatus::ErrorCode::NO_SPACE:
            return "No space";
    }
}

FiemapStatus::ErrorCode FiemapStatus::ErrorCodeFromErrno(int error_num) {
    switch (error_num) {
        case 0:
            return ErrorCode::SUCCESS;
        case ENOSPC:
            return ErrorCode::NO_SPACE;
        default:
            return ErrorCode::ERROR;
    }
}

}  // namespace android::fiemap
