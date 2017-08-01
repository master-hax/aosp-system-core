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

// This file contains primitives for returning a successful result along with an optional
// arbitrarily typed return value or for returning a failure result along with an optional string
// indicating why the function failed.

// There 2 public types and 4 public functions that implement this functionality
//
// Result<T> either contains a member of type T that can be accessed using similar semantics as
// std::optional<T> or it contains a std::string describing an error, which can be accessed via
// Result<T>::error().
//
// Success is a typedef that aids in creating Result<T> that do not contain a return value.
// Result<Success> is the correct return type for a function that either returns successfully or
// returns an error value.
//
// Ok(T&& t) and Ok() construct Result<T> containing a success.
// Ok(T&& t) constructs a successful Result<T> with its parameter as the contents.
// Ok() constructs a Result<Success>.
//
// Err() and PErr() take an ostream and use it to construct a Result<T> containing a failure.
// PErr() additionally appends ": " + strerror(errno) to the end of the failure string to aid in
// interacting with C APIs.  For example,
//   passwd* pwd = getpwnam(name.c_str());
//   if (!pwd) return PErr() << "getpwnam failed";

// An example of how to use these is below:
// Result<U> CalculateResult(const T& input) {
//   U output;
//   if (!SomeOtherCppFunction(input, &output)) {
//     return Err() << "SomeOtherCppFunction(" << input << ") failed";
//   }
//   if (!c_api_function(output)) {
//     return PErr() << "c_api_function(" << output << ") failed";
//   }
//   return Ok(output);
// }
//
// auto output = CalculateResult(input);
// if (!output) return Err() << "CalculateResult failed: " << output.error();
// UseOutput(*output);

#ifndef _INIT_ERROR_HANDLING_H
#define _INIT_ERROR_HANDLING_H

#include "errno.h"

#include <iostream>
#include <sstream>
#include <string>
#include <variant>

namespace android {
namespace init {

class ErrBuilder {
    friend ErrBuilder Err();
    friend ErrBuilder PErr();

  public:
    template <typename T>
    ErrBuilder&& operator<<(T&& t) {
        ss_ << std::forward<T>(t);
        return std::move(*this);
    }

    const std::string str() const {
        if (append_errno_) {
            return ss_.str() + ": " + strerror(errno);
        }
        return ss_.str();
    }

    ErrBuilder(const ErrBuilder&) = delete;
    ErrBuilder(ErrBuilder&&) = delete;
    ErrBuilder& operator=(const ErrBuilder&) = delete;
    ErrBuilder& operator=(ErrBuilder&&) = delete;

  private:
    ErrBuilder(bool append_errno) : append_errno_(append_errno) {}
    std::stringstream ss_;
    bool append_errno_;
};

inline ErrBuilder Err() {
    return ErrBuilder(false);
}

inline ErrBuilder PErr() {
    return ErrBuilder(true);
}

template <typename T>
class Result {
  public:
    template <typename U>
    explicit Result(U&& result) : contents_(std::in_place_index_t<0>(), std::forward<U>(result)) {}
    // This below constructor is purposefully not explicit.
    Result(ErrBuilder&& fb) : contents_(std::in_place_index_t<1>(), fb.str()) {}

    bool has_value() const { return contents_.index() == 0; }
    T& value() & { return std::get<0>(contents_); }
    const T& value() const & { return std::get<0>(contents_); }
    T&& value() const && { return std::get<0>(std::move(contents_)); }
    const std::string& error() const & { return std::get<1>(contents_); }
    std::string&& error() const && { return std::get<1>(std::move(contents_)); }

    operator bool() const { return has_value(); }
    T& operator*() & { return value(); }
    const T& operator*() const & { return value(); }
    T&& operator*() const && { return value(); }
    T* operator->() const { return &value(); }

  private:
    std::variant<T, std::string> contents_;
};

template <typename T>
inline Result<typename std::decay<T>::type> Ok(T&& t) {
    return Result<typename std::decay<T>::type>(std::forward<T>(t));
}

inline Result<std::monostate> Ok() {
    return Result<std::monostate>(std::monostate());
}

using Success = std::monostate;

}  // namespace init
}  // namespace android

#endif
