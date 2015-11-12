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

#ifndef ANDROID_SMART_FILE_DESCRIPTOR_H
#define ANDROID_SMART_FILE_DESCRIPTOR_H

#include <stdint.h>
#include <unistd.h>

#include <map>
#include <iostream>

namespace android {

class sfd {
 public:
  static sfd dup(int i) {
    return sfd(::dup(i));
  }

  static sfd dup(const sfd& o) {
    return sfd::dup(o.value_);
  }

  inline sfd() : value_(-1) {}

  explicit sfd(int value) : value_(value) {}
  ~sfd() { clear(); }

  sfd(const sfd& other) = delete;
  sfd& operator = (sfd& s) = delete;

  sfd(sfd&& other) : value_(other.release()) {}
  sfd& operator = (sfd&& s) {
    reset(s.release());
    return *this;
  }

  inline void reset(int new_value) {
    if (value_ >= 0)
      close(value_);
    value_ = new_value;
  }

  inline void clear() {
    reset(-1);
  }

  inline int get() const { return value_; }

  inline int release() {
    int ret = value_;
    value_ = -1;
    return ret;
  }

 private:    
  int value_;
};

}; // namespace android

#endif // ANDROID_SMART_FILE_DESCRIPTOR_H
