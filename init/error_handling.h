/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef _INIT_ERROR_HANDLING_H
#define _INIT_ERROR_HANDLING_H

#include <iostream>
#include <sstream>
#include <string>
#include <variant>

namespace android {
namespace init {

struct ErrBuilder {
    ErrBuilder() {}
    std::stringstream ss;
};

template <typename T>
ErrBuilder&& operator<<(ErrBuilder&& fb, T&& t) {
    fb.ss << std::forward<T>(t);
    return std::move(fb);
}

inline ErrBuilder Err() {
    return ErrBuilder();
}

template <typename T>
class Result {
  public:
    template <typename U>
    Result(U&& result) : contents_(std::in_place_index_t<0>(), std::forward<U>(result)) {}
    Result(ErrBuilder&& fb) : contents_(std::in_place_index_t<1>(), fb.ss.str()) {}

    bool success() const { return contents_.index() == 0; }
    T& value() & { return std::get<0>(contents_); }
    const T& value() const & { return std::get<0>(contents_); }
    T&& value() const && { return std::get<0>(std::move(contents_)); }
    const std::string& error() const & { return std::get<1>(contents_); }
    std::string&& error() const && { return std::get<1>(std::move(contents_)); }

    operator bool() const { return success(); }
    T& operator*() & { return value(); }
    const T& operator*() const & { return value(); }
    T&& operator*() const && { return value(); }
    T* operator->() const { return &value(); }

  private:
    std::variant<T, std::string> contents_;
};

template <typename T>
inline Result<T> Ok(T&& t) {
    return Result<T>(std::forward<T>(t));
}

using SuccessOrErr = Result<bool>;

inline SuccessOrErr Success() {
    return SuccessOrErr(true);
}

}  // namespace init
}  // namespace android

#endif
