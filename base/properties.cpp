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

#include "android-base/properties.h"

#include <string>

#include <sys/system_properties.h>

namespace android {
namespace base {

void GetProperty(const std::string& key, std::string* value) {
  // If the property doesn't exist, leave `value` alone in case the
  // caller supplied a default value.
  const prop_info* pi = __system_property_find(key.c_str());
  if (pi == nullptr) return;

  char buf[PROP_VALUE_MAX];
  __system_property_read(pi, nullptr, buf);
  value->assign(buf);
}

bool SetProperty(const std::string& key, const std::string& value) {
  return (__system_property_set(key.c_str(), value.c_str()) == 0);
}

}  // namespace base
}  // namespace android
