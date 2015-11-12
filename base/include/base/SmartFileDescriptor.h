/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef ANDROID_BASE_SMART_FILE_DESCRIPTOR_H
#define ANDROID_BASE_SMART_FILE_DESCRIPTOR_H

#include <stdint.h>
#include <unistd.h>

namespace android {
namespace base {

class SmartFileDescriptor {
 public:
  static SmartFileDescriptor Dup(int i) {
    return SmartFileDescriptor(dup(i));
  }

  static SmartFileDescriptor Dup(const SmartFileDescriptor& o) {
    return SmartFileDescriptor::Dup(o.value_);
  }

  inline SmartFileDescriptor() : value_(-1) {}

  explicit SmartFileDescriptor(int value) : value_(value) {}
  ~SmartFileDescriptor() { Clear(); }

  SmartFileDescriptor(const SmartFileDescriptor& other) = delete;
  SmartFileDescriptor& operator = (SmartFileDescriptor& s) = delete;

  SmartFileDescriptor(SmartFileDescriptor&& other) : value_(other.Release()) {}
  SmartFileDescriptor& operator = (SmartFileDescriptor&& s) {
    Reset(s.Release());
    return *this;
  }

  inline void Reset(int new_value) {
    if (value_ >= 0)
      close(value_);
    value_ = new_value;
  }

  inline void Clear() {
    Reset(-1);
  }

  inline int Get() const { return value_; }

  inline int Release() {
    int ret = value_;
    value_ = -1;
    return ret;
  }

 private:    
  int value_;
};

}; // namespace base
}; // namespace android

#endif // ANDROID_BASE_SMART_FILE_DESCRIPTOR_H
