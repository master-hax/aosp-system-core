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

void GetProperty(const std::string& key, std::string* value);

bool SetProperty(const std::string& key, const std::string& value);

} // namespace base
} // namespace android

#endif  // ANDROID_BASE_MEMORY_H
