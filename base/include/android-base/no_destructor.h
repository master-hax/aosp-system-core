#pragma once

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

// Copyright 2015 The Chromium Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <utility>

#include "android-base/macros.h"

namespace android {
namespace base {

// A wrapper that makes it easy to create an object of type T with static
// storage duration that:
// - is only constructed on first access
// - never invokes the destructor
// in order to satisfy the styleguide ban on global constructors and
// destructors.
//
// Runtime constant example:
// const std::string& GetLineSeparator() {
//  // Forwards to std::string(size_t, char, const Allocator&) constructor.
//   static const base::NoDestructor<std::string> s(5, '-');
//   return *s;
// }
//
// More complex initialization with a lambda:
// const std::string& GetSessionNonce() {
//   static const base::NoDestructor<std::string> nonce([] {
//     std::string s(16);
//     crypto::RandString(s.data(), s.size());
//     return s;
//   }());
//   return *nonce;
// }
//
// NoDestructor<T> stores the object inline, so it also avoids a pointer
// indirection and a malloc. Also note that since C++11 static local variable
// initialization is thread-safe and so is this pattern. Code should prefer to
// use NoDestructor<T> over:
// - A function scoped static T* or T& that is dynamically initialized.
// - A global base::LazyInstance<T>.
//
// Note that since the destructor is never run, this *will* leak memory if used
// as a stack or member variable. Furthermore, a NoDestructor<T> should never
// have global scope as that may require a static initializer.
template <typename T>
class NoDestructor {
 public:
  // Not constexpr; just write static constexpr T x = ...; if the value should
  // be a constexpr.
  template <typename... Args>
  explicit NoDestructor(Args&&... args) {
    new (storage_) T(std::forward<Args>(args)...);
  }

  // Allows copy and move construction of the contained type, to allow
  // construction from an initializer list, e.g. for std::vector.
  explicit NoDestructor(const T& x) { new (storage_) T(x); }
  explicit NoDestructor(T&& x) { new (storage_) T(std::move(x)); }

  NoDestructor(const NoDestructor&) = delete;
  NoDestructor& operator=(const NoDestructor&) = delete;

  ~NoDestructor() = default;

  const T& operator*() const { return *get(); }
  T& operator*() { return *get(); }

  const T* operator->() const { return get(); }
  T* operator->() { return get(); }

  const T* get() const { return reinterpret_cast<const T*>(storage_); }
  T* get() { return reinterpret_cast<T*>(storage_); }

 private:
  alignas(T) char storage_[sizeof(T)];
};

}  // namespace base
}  // namespace android
