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

#ifndef ANDROID_BASE_PROPERTIES_H
#define ANDROID_BASE_PROPERTIES_H

#include <sys/cdefs.h>

#if !defined(__BIONIC__)
#error Only bionic supports system properties.
#endif

#include <string>

namespace android {
namespace base {

// Copies the current value of the system property `key` to `value`.
// Leaves `value` untouched if the property doesn't exist (so you
// can assign any desired default before calling this function).
void GetProperty(const std::string& key, std::string* value);

// Returns true if the system property `key` has the value "1", "y", "yes", "on", or "true",
// false for "0", "n", "no", "off", or "false", or `default_value` otherwise.
bool GetBoolProperty(const std::string& key, bool default_value);

// Sets the system property `key` to `value`.
// Note that system property setting is inherently asynchronous so the
// return value isn't particularly meaningful, and immediately reading
// back the value won't necessarily tell you whether or not your call
// succeeded.
bool SetProperty(const std::string& key, const std::string& value);

} // namespace base
} // namespace android

#endif  // ANDROID_BASE_MEMORY_H
