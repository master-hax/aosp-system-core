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

// There are 3 classes that implement this functionality and one additional helper type.
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
// Error and ErrnoError are used to construct a Result<T> that has failed.  The Error class takes
// an ostream as an input and are implicitly cast to a Result<T> containing that failure.
// ErrnoError() is a helper function to create an Error class that appends ": " + strerror(errno)
// to the end of the failure string to aid in interacting with C APIs.  Alternatively, an errno
// value can be directly specified via the Error() constructor.
//
// Error and ErrnoError can be constructed from variadic arguments, in which case the arguments
// are put to the ostream in sequence. e.g., Error("failed when input is ", input) is equivalent
// to Error() << "failed when input is " << input.
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
//     return Error("SomeOtherCppFunction(", input, ") failed");
//   }
//   if (!c_api_function(output)) {
//     return ErrnoError("c_api_function(", output, ") failed");
//   }
//   return output;
// }
//
// auto output = CalculateResult(input);
// if (!output) return Error("CalculateResult failed: ", output.error());
// UseOutput(*output);

#pragma once

#include <errno.h>

#include <sstream>
#include <string>

#include "android-base/expected.h"

namespace android {
namespace base {

struct ResultError {
  template <typename T>
  ResultError(T&& message, int code)
      : message_(std::forward<T>(message)), code_(code) {}

  template <typename T>
  operator android::base::expected<T, ResultError>() {
    return android::base::unexpected(ResultError(message_, code_));
  }

  std::string message() const { return message_; }
  int code() const { return code_; }

 private:
  std::string message_;
  int code_;
};

inline bool operator==(const ResultError& lhs, const ResultError& rhs) {
  return lhs.message() == rhs.message() && lhs.code() == rhs.code();
}

inline bool operator!=(const ResultError& lhs, const ResultError& rhs) {
  return !(lhs == rhs);
}

inline std::ostream& operator<<(std::ostream& os, const ResultError& t) {
  os << t.message();
  return os;
}

namespace {

inline void StringStreamConcat(std::stringstream&) {
  return;
}

template <typename T, typename... Ts>
inline void StringStreamConcat(std::stringstream& ss, T&& t, Ts&&... ts) {
  ss << t;
  StringStreamConcat(ss, ts...);
}

}  // namespace

class Error {
 public:
  Error() : errno_(0), append_errno_(false) {}
  template <typename T, typename... Args, std::enable_if_t<!std::is_same_v<Error*, T>>* = nullptr>
  Error(T t, Args&&... args) : Error() {
    StringStreamConcat(ss_, t, args...);
  }

  template <typename T>
  operator android::base::expected<T, ResultError>() {
    return android::base::unexpected(ResultError(str(), errno_));
  }

  template <typename T>
  Error& operator<<(T&& t) {
    int saved = errno;
    ss_ << t;
    errno = saved;
    return *this;
  }

  Error& operator<<(const ResultError& result_error) {
    if (!result_error.message().empty()) {
      (*this) << result_error.message();
    }
    append_errno_ = true;
    errno_ = result_error.code();
    return *this;
  }

  const std::string str() const {
    std::string str = ss_.str();
    if (append_errno_) {
      if (str.empty()) {
        return strerror(errno_);
      }
      return std::move(str) + ": " + strerror(errno_);
    }
    return str;
  }

  Error(const Error&) = delete;
  Error(Error&&) = delete;
  Error& operator=(const Error&) = delete;
  Error& operator=(Error&&) = delete;

  friend Error ErrnoError();
  template <typename... Args>
  friend Error ErrnoError(Args&&... args);

 private:
  Error(Error*, int errno_) : errno_(errno_), append_errno_(true) {}
  Error(Error*, int errno_, std::string&& message) : errno_(errno_), append_errno_(true) {
    (*this) << message;
  }
  std::stringstream ss_;
  int errno_;
  bool append_errno_;
};

inline Error ErrnoError() {
  return Error(static_cast<Error*>(nullptr), errno);
}

template <typename... Args>
inline Error ErrnoError(Args&&... args) {
  std::stringstream ss;
  StringStreamConcat(ss, args...);
  return Error(static_cast<Error*>(nullptr), errno, ss.str());
}

template <typename T>
using Result = android::base::expected<T, ResultError>;

// Usage: `Result<Success>` as a result type that doesn't contain a value.
// Use `return {}` or `return Success()` to return with success.
using Success = std::monostate;

}  // namespace base
}  // namespace android
