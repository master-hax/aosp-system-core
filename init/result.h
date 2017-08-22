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

// This file contains classes for returning a successful result along with an optional
// arbitrarily typed return value or for returning a failure result along with an optional string
// indicating why the function failed.

// There are 4 classes that implement this functionality and one additional helper type.
//
// Result<T> either contains a member of type T that can be accessed using similar semantics as
// std::optional<T> or it contains a ResultError describing an error, which can be accessed via
// Result<T>::error().
//
// ResultError is a type that contains both a std::string describing the error and a copy of errno
// from when the error occurred.  ResultError can be used in an ostream directly to print its
// string value.
//
// Success is a typedef that aids in creating Result<T> that do not contain a return value.
// Result<Success> is the correct return type for a function that either returns successfully or
// returns an error value.  Returning Success() from a function that returns Result<Success> is the
// correct way to indicate that a function without a return type has completed successfully.
//
// A successful Result<T> is constructed implicitly from any type that can be implicitly converted
// to T or from the constructor arguments for T.  This allows you to return a type T directly from
// a function that returns Result<T>.
//
// Error and ErrnoError are used to construct a Result<T> that has failed.  Each of these classes
// take an ostream as an input and are implicitly cast to a Result<T> containing that failure.
// ErrnoError() additionally appends ": " + strerror(errno) to the end of the failure string to aid
// in interacting with C APIs.
//
// ResultError can be used in the ostream when using Error to construct a Result<T>.  In this case,
// the string that the ResultError takes is passed through the stream normally, but the errno is
// passed to the Result<T>.  This can be used to pass errno from a failing C function up multiple
// callers.
//
// ResultError can also directly construct a Result<T>.  This is particularly useful if you have a
// function that return Result<T> but you have a Result<U> and want to return its error.  In this
// case, you can return the .error() from the Result<U> to construct the Result<T>.

// An example of how to use these is below:
// Result<U> CalculateResult(const T& input) {
//   U output;
//   if (!SomeOtherCppFunction(input, &output)) {
//     return Error() << "SomeOtherCppFunction(" << input << ") failed";
//   }
//   if (!c_api_function(output)) {
//     return ErrnoError() << "c_api_function(" << output << ") failed";
//   }
//   return output;
// }
//
// auto output = CalculateResult(input);
// if (!output) return Error() << "CalculateResult failed: " << output.error();
// UseOutput(*output);

#ifndef _INIT_RESULT_H
#define _INIT_RESULT_H

#include <errno.h>

#include <sstream>
#include <string>
#include <variant>

namespace android {
namespace init {

struct ResultError {
    template <typename T>
    ResultError(T&& error_string, int error_errno)
        : error_string(std::forward<T>(error_string)), error_errno(error_errno) {}

    std::string error_string;
    int error_errno;
};

inline std::ostream& operator<<(std::ostream& os, const ResultError& t) {
    os << t.error_string;
    return os;
}

inline std::ostream& operator<<(std::ostream& os, ResultError&& t) {
    os << std::move(t.error_string);
    return os;
}

class Error {
  public:
    Error() : append_errno_(0) {}

    template <typename T>
    Error&& operator<<(T&& t) {
        ss_ << std::forward<T>(t);
        return std::move(*this);
    }

    Error&& operator<<(const ResultError& result_error) {
        ss_ << result_error.error_string;
        append_errno_ = result_error.error_errno;
        return std::move(*this);
    }

    Error&& operator<<(ResultError&& result_error) {
        ss_ << std::move(result_error.error_string);
        append_errno_ = result_error.error_errno;
        return std::move(*this);
    }

    const std::string str() const {
        std::string str = ss_.str();
        if (append_errno_) {
            if (str.empty()) {
                return strerror(append_errno_);
            }
            return str + ": " + strerror(append_errno_);
        }
        return str;
    }

    int append_errno() const { return append_errno_; }

    Error(const Error&) = delete;
    Error(Error&&) = delete;
    Error& operator=(const Error&) = delete;
    Error& operator=(Error&&) = delete;

  protected:
    Error(int append_errno) : append_errno_(append_errno) {}

  private:
    std::stringstream ss_;
    std::string prev_result_error_;
    int append_errno_;
};

class ErrnoError : public Error {
  public:
    ErrnoError() : Error(errno) {}
};

template <typename T>
class Result {
  public:
    template <typename... U>
    Result(U&&... result) : contents_(std::in_place_index_t<0>(), std::forward<U>(result)...) {}

    Result(Error&& error)
        : contents_(std::in_place_index_t<1>(), error.str(), error.append_errno()) {}
    Result(ErrnoError&& error)
        : contents_(std::in_place_index_t<1>(), error.str(), error.append_errno()) {}
    Result(const ResultError& result_error)
        : contents_(std::in_place_index_t<1>(), result_error.error_string,
                    result_error.error_errno) {}
    Result(ResultError&& result_error)
        : contents_(std::in_place_index_t<1>(), std::move(result_error.error_string),
                    result_error.error_errno) {}

    bool has_value() const { return contents_.index() == 0; }

    T& value() & { return std::get<0>(contents_); }
    const T& value() const & { return std::get<0>(contents_); }
    T&& value() && { return std::get<0>(std::move(contents_)); }
    const T&& value() const && { return std::get<0>(std::move(contents_)); }

    const ResultError& error() const & { return std::get<1>(contents_); }
    ResultError&& error() && { return std::get<1>(std::move(contents_)); }
    const ResultError&& error() const && { return std::get<1>(std::move(contents_)); }

    const std::string& error_string() const & { return std::get<1>(contents_).error_string; }
    std::string&& error_string() && { return std::get<1>(std::move(contents_)).error_string; }
    const std::string&& error_string() const && {
        return std::get<1>(std::move(contents_)).error_string;
    }

    int error_errno() const { return std::get<1>(contents_).error_errno; }

    explicit operator bool() const { return has_value(); }

    T& operator*() & { return value(); }
    const T& operator*() const & { return value(); }
    T&& operator*() && { return std::move(value()); }
    const T&& operator*() const && { return std::move(value()); }

    T* operator->() { return &value(); }
    const T* operator->() const { return &value(); }

  private:
    std::variant<T, ResultError> contents_;
};

using Success = std::monostate;

}  // namespace init
}  // namespace android

#endif
