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

#include "android-base/parsebool.h"
#include <errno.h>

namespace android {
namespace base {

bool ParseBool(std::string_view s, bool* out) {
  if (s == "1" || s == "y" || s == "yes" || s == "on" || s == "true") {
    *out = true;
    return true;
  }
  if (s == "0" || s == "n" || s == "no" || s == "off" || s == "false") {
    *out = false;
    return true;
  }
  errno = EINVAL;
  return false;
}

}  // namespace base
}  // namespace android
