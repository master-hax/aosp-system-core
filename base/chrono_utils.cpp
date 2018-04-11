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

#include "android-base/chrono_utils.h"

#include <time.h>

#if defined(__BIONIC__)
#include "android-base/properties.h"
#endif

namespace android {
namespace base {

namespace {

int64_t GetBootTimeOffsetInNanoseconds() {
#if defined(__BIONIC__)
  static const int64_t boottime_offset = GetIntProperty<int64_t>("ro.boot.boottime_offset", 0);
#else
  static constexpr const int64_t boottime_offset = 0;
#endif
  return boottime_offset;
}

void OffsetTime(timespec* ts) {
  int64_t boottime_offset = GetBootTimeOffsetInNanoseconds();
  int64_t sign = 1;
  constexpr int64_t kNanosecondsPerSecond = 1000000000ll;
  if (boottime_offset < 0) {
    // In order to avoid performing modular arithmetic with negative values
    // (since the behavior or the % and / operators are not consistent with each
    // other), we always have |boottime_offset| be positive and then change the
    // sign of the resulting value.
    boottime_offset *= -1;
    sign = -1;
  }
  ts->tv_nsec -= sign * (boottime_offset % kNanosecondsPerSecond);
  ts->tv_sec -= sign * (boottime_offset / kNanosecondsPerSecond);
  if (ts->tv_nsec < 0) {
    ts->tv_nsec += kNanosecondsPerSecond;
    ts->tv_sec--;
  }
  if (ts->tv_nsec >= kNanosecondsPerSecond) {
    ts->tv_nsec -= kNanosecondsPerSecond;
    ts->tv_sec++;
  }
}

}  // namespace

boot_clock::time_point boot_clock::now() {
#ifdef __linux__
  timespec ts;
  clock_gettime(CLOCK_BOOTTIME, &ts);
  OffsetTime(&ts);
  return boot_clock::time_point(std::chrono::seconds(ts.tv_sec) +
                                std::chrono::nanoseconds(ts.tv_nsec));
#else
  // Darwin and Windows do not support clock_gettime.
  return boot_clock::time_point();
#endif  // __linux__
}

std::ostream& operator<<(std::ostream& os, const Timer& t) {
  os << t.duration().count() << "ms";
  return os;
}

}  // namespace base
}  // namespace android
