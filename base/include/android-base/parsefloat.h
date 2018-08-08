/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <errno.h>
#include <stdlib.h>

#include <limits>

namespace android {
namespace base {

// Parse float value in the string 's' and sets 'out' to that value if it is specified.
// Optionally allows the caller to define a 'min' and 'max' beyond which
// otherwise valid values will be rejected. Returns boolean success.
static inline bool ParseFloat(const char* s, float* out,
                              float min = std::numeric_limits<float>::lowest(),
                              float max = std::numeric_limits<float>::max()) {
  errno = 0;
  char* end;
  float result = strtof(s, &end);
  if (errno != 0 || s == end || *end != '\0') {
    return false;
  }
  if (result < min || max < result) {
    return false;
  }
  if (out != nullptr) {
    *out = result;
  }
  return true;
}

}  // namespace base
}  // namespace android
