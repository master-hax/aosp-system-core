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

#include <utility>

namespace android {
namespace base {

template <typename T>
struct NoDestruct {
  template <typename... Args>
  NoDestruct(Args&&... args) {
    new (data_) T(std::forward<Args>(args)...);
  }

  const T* get() const { return reinterpret_cast<const T*>(data_); }
  T* get() { return reinterpret_cast<T*>(data_); }

  const T& operator*() const { return *get(); }
  T& operator*() { return *get(); }

  const T* operator->() const { return get(); }
  T* operator->() { return get(); }

 private:
  alignas(alignof(T)) char data_[sizeof(T)];
};

}  // namespace base
}  // namespace android
