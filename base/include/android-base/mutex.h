/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _WIN32
#include <mutex>
#else
#include <windows.h>
#endif

namespace android {
namespace base {
#ifndef _WIN32
using std::mutex;
#else
class mutex {
 public:
  mutex() {
    InitializeCriticalSection(&critical_section_);
  }
  ~mutex() {
    DeleteCriticalSection(&critical_section_);
  }

  void lock() {
    EnterCriticalSection(&critical_section_);
  }

  void unlock() {
    LeaveCriticalSection(&critical_section_);
  }

 private:
  CRITICAL_SECTION critical_section_;
};
#endif
} // namespace base
} // namespace android
