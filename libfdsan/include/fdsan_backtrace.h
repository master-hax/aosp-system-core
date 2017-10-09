#pragma once

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

// Implemented in libfdsan_standalone.
struct FdsanBacktrace;

extern "C" void fdsan_free(FdsanBacktrace*);
extern "C" FdsanBacktrace* fdsan_record_backtrace();
extern "C" void fdsan_report_backtrace(const FdsanBacktrace*);

struct unique_backtrace {
  unique_backtrace(FdsanBacktrace* ptr = nullptr) : ptr_(ptr) {}
  ~unique_backtrace() { reset(); }

  unique_backtrace(const unique_backtrace& copy) = delete;
  unique_backtrace(unique_backtrace&& move) { reset(move.release()); }

  unique_backtrace& operator=(const unique_backtrace& copy) = delete;
  unique_backtrace& operator=(unique_backtrace&& move) {
    reset(move.release());
    return *this;
  }

  void reset(FdsanBacktrace* ptr = nullptr) {
    if (ptr_) {
      fdsan_free(ptr_);
    }
    ptr_ = ptr;
  }

  FdsanBacktrace* release() {
    FdsanBacktrace* result = ptr_;
    ptr_ = nullptr;
    return result;
  }

  FdsanBacktrace* get() { return ptr_; }
  const FdsanBacktrace* get() const { return ptr_; }

 private:
  FdsanBacktrace* ptr_;
};
