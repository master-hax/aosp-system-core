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

#pragma once

#include <sys/cdefs.h>

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>

namespace android {
namespace base {

// N.B. the functions taking std::string references are inefficient
// and deprecated. New users should just use FindProperty and the
// PropertyHandle-accepting functions.

// Opaque property handle. It is a programming error to pass a null
// PropertyHandle to a function expecting a property handle.
struct PropertyHandle;

// Returns the current value of the system property `key`,
// or `default_value` if the property is empty or doesn't exist.
std::string GetProperty(const std::string& key, const std::string& default_value);

// Use a function signature-compatible with
// __system_property_read_callback (but slightly cumbersome in C++) so
// that we can pass the callback directly to the underlying C
// property API.
using GetPropertyCallback = void (*)(void* cookie, const char* name, const char* value,
                                     uint32_t serial);

// Read a property value directly from the property system.
// callback may be invoked multiple times if the property value
// changes while it's being read! (Callback being called multiple
// times is extremely unlikely, however.) Unlike other functions that
// accept PropertyHandle* parameters, this one requires a
// non-null PropertyHandle.
void GetPropertyWithCallback(PropertyHandle* handle_must_not_be_null, GetPropertyCallback callback,
                             void* cookie);

// Returns true if the system property `key` has the value "1", "y", "yes", "on", or "true",
// false for "0", "n", "no", "off", or "false", or `default_value` otherwise.
bool GetBoolProperty(const std::string& key, bool default_value);
bool GetBoolProperty(PropertyHandle* handle, bool default_value);

// Returns the signed integer corresponding to the system property `key`.
// If the property is empty, doesn't exist, doesn't have an integer value, or is outside
// the optional bounds, returns `default_value`.
template <typename T> T GetIntProperty(const std::string& key,
                                       T default_value,
                                       T min = std::numeric_limits<T>::min(),
                                       T max = std::numeric_limits<T>::max());
template <typename T>
T GetIntProperty(PropertyHandle* handle_must_not_be_null, T default_value,
                 T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max());

// Returns the unsigned integer corresponding to the system property `key`.
// If the property is empty, doesn't exist, doesn't have an integer value, or is outside
// the optional bound, returns `default_value`.
template <typename T> T GetUintProperty(const std::string& key,
                                        T default_value,
                                        T max = std::numeric_limits<T>::max());
template <typename T>
T GetUintProperty(PropertyHandle* handle_must_not_be_null, T default_value,
                  T max = std::numeric_limits<T>::max());

// Sets the system property `key` to `value`.
bool SetProperty(const std::string& key, const std::string& value);

// Find an existing property or return nullptr if that property
// doesn't exist yet. The lifetime of the returned PropertyHandle*
// is unlimited.
PropertyHandle* FindProperty(const char* name /*non-null*/);

// Waits for the system property `key` to have the value `expected_value`.
// Times out after `relative_timeout`.
// Returns true on success, false on timeout.
#if defined(__BIONIC__)
bool WaitForProperty(const std::string& key, const std::string& expected_value,
                     std::chrono::milliseconds relative_timeout = std::chrono::milliseconds::max());
#endif

// Waits for the system property `key` to be created.
// Times out after `relative_timeout`.
// Returns true on success, false on timeout.
#if defined(__BIONIC__)
bool WaitForPropertyCreation(const std::string& key, std::chrono::milliseconds relative_timeout =
                                                         std::chrono::milliseconds::max());
#endif

} // namespace base
} // namespace android
