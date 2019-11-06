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

#if defined(__BIONIC__)
#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/system_properties.h>
#include <sys/_system_properties.h>
#endif

#include <algorithm>
#include <chrono>
#include <limits>
#include <map>
#include <string>
#include <string_view>

#include <android-base/parseint.h>

namespace android {
namespace base {

#if !defined(__BIONIC__)
// std::map is a node container, so pointers to elements remain
// valid indefinitely.
using FakeProperties = std::map<std::string, std::string>;
static FakeProperties& g_properties = *new FakeProperties;
static int __system_property_set(const char* key, const char* value) {
  g_properties[key] = value;
  return 0;
}
static const std::string& handle_to_name(PropertyHandle* handle) {
  return reinterpret_cast<FakeProperties::value_type*>(handle)->first;
}
static const std::string& handle_to_value(PropertyHandle* handle) {
  return reinterpret_cast<FakeProperties::value_type*>(handle)->second;
}
static constexpr size_t PROP_VALUE_MAX = 96;
#else
static const prop_info* handle_to_pi(PropertyHandle* handle) {
  return reinterpret_cast<const prop_info*>(handle);
}
#endif

struct ShortPropertyValue {
  char value[PROP_VALUE_MAX];  // NUL-terminated
  size_t len;
};

static bool GetShortProperty(PropertyHandle* handle, ShortPropertyValue* out);

bool GetBoolProperty(const std::string& key, bool default_value) {
  PropertyHandle* handle = FindProperty(key.c_str());
  return handle ? GetBoolProperty(handle, default_value) : default_value;
}

template <typename T>
T GetIntProperty(const std::string& key, T default_value, T min, T max) {
  PropertyHandle* handle = FindProperty(key.c_str());
  return handle ? GetIntProperty<T>(handle, default_value, min, max) : default_value;
}

template <typename T>
T GetUintProperty(const std::string& key, T default_value, T max) {
  PropertyHandle* handle = FindProperty(key.c_str());
  return handle ? GetUintProperty<T>(handle, default_value, max) : default_value;
}

bool GetBoolProperty(PropertyHandle* handle_must_not_be_null, bool default_value) {
  ShortPropertyValue value_buf;
  if (!GetShortProperty(handle_must_not_be_null, &value_buf)) {
    return default_value;
  }
  std::string_view value = std::string_view(value_buf.value, value_buf.len);
  if (value == "1" || value == "y" || value == "yes" || value == "on" || value == "true") {
    return true;
  } else if (value == "0" || value == "n" || value == "no" || value == "off" || value == "false") {
    return false;
  }
  return default_value;
}

template <typename T>
T GetIntProperty(PropertyHandle* handle_must_not_be_null, T default_value, T min, T max) {
  ShortPropertyValue value_buf;
  if (!GetShortProperty(handle_must_not_be_null, &value_buf)) {
    return default_value;
  }
  const char* value = value_buf.value;
  T result;
  if (value[0] && android::base::ParseInt(value, &result, min, max)) return result;
  return default_value;
}

template <typename T>
T GetUintProperty(PropertyHandle* handle_must_not_be_null, T default_value, T max) {
  ShortPropertyValue value_buf;
  if (!GetShortProperty(handle_must_not_be_null, &value_buf)) {
    return default_value;
  }
  const char* value = value_buf.value;
  T result;
  if (value[0] && android::base::ParseUint(value, &result, max)) return result;
  return default_value;
}

template int8_t GetIntProperty(const std::string&, int8_t, int8_t, int8_t);
template int16_t GetIntProperty(const std::string&, int16_t, int16_t, int16_t);
template int32_t GetIntProperty(const std::string&, int32_t, int32_t, int32_t);
template int64_t GetIntProperty(const std::string&, int64_t, int64_t, int64_t);

template int8_t GetIntProperty(PropertyHandle*, int8_t, int8_t, int8_t);
template int16_t GetIntProperty(PropertyHandle*, int16_t, int16_t, int16_t);
template int32_t GetIntProperty(PropertyHandle*, int32_t, int32_t, int32_t);
template int64_t GetIntProperty(PropertyHandle*, int64_t, int64_t, int64_t);

template uint8_t GetUintProperty(const std::string&, uint8_t, uint8_t);
template uint16_t GetUintProperty(const std::string&, uint16_t, uint16_t);
template uint32_t GetUintProperty(const std::string&, uint32_t, uint32_t);
template uint64_t GetUintProperty(const std::string&, uint64_t, uint64_t);

template uint8_t GetUintProperty(PropertyHandle*, uint8_t, uint8_t);
template uint16_t GetUintProperty(PropertyHandle*, uint16_t, uint16_t);
template uint32_t GetUintProperty(PropertyHandle*, uint32_t, uint32_t);
template uint64_t GetUintProperty(PropertyHandle*, uint64_t, uint64_t);

std::string GetProperty(const std::string& key, const std::string& default_value) {
  PropertyHandle* handle = FindProperty(key.c_str());
  if (!handle) {
    return default_value;
  }
  std::string property_value;
  GetPropertyWithCallback(
      handle,
      [](void* cookie, const char*, const char* value, unsigned) {
        auto property_value = reinterpret_cast<std::string*>(cookie);
        *property_value = value;
      },
      &property_value);
  if (property_value.empty()) {
    property_value = default_value;
  }
  return property_value;
}

bool GetShortProperty(PropertyHandle* handle /*nullable*/, ShortPropertyValue* out) {
  GetPropertyWithCallback(
      handle,
      [](void* cookie, const char*, const char* value, unsigned) {
        auto* out = reinterpret_cast<ShortPropertyValue*>(cookie);
        out->len = strlen(value);
        if (out->len < sizeof(out->value)) {
          memcpy(out->value, value, out->len + 1);
        }
      },
      out);
  bool truncated = out->len >= sizeof(out->value);
  return !truncated;
}

void GetPropertyWithCallback(PropertyHandle* handle_must_not_be_null, GetPropertyCallback callback,
                             void* cookie) {
#if defined(__BIONIC__)
  const prop_info* pi = handle_to_pi(handle_must_not_be_null);
  __system_property_read_callback(pi, callback, cookie);
#else
  callback(cookie, handle_to_name(handle_must_not_be_null).c_str(),
           handle_to_value(handle_must_not_be_null).c_str(), 1 /* fake serial */);
#endif
}

bool SetProperty(const std::string& key, const std::string& value) {
  return (__system_property_set(key.c_str(), value.c_str()) == 0);
}

PropertyHandle* FindProperty(const char* name /*non-null*/) {
#if defined(__BIONIC__)
  const prop_info* pi = __system_property_find(name);
  return const_cast<PropertyHandle*>(reinterpret_cast<const PropertyHandle*>(pi));
#else
  auto it = g_properties.find(name);
  if (it == g_properties.end()) {
    return nullptr;
  }
  return reinterpret_cast<PropertyHandle*>(&*it);  // Stable
#endif
}

#if defined(__BIONIC__)

struct WaitForPropertyData {
  bool done;
  const std::string* expected_value;
  unsigned last_read_serial;
};

static void WaitForPropertyCallback(void* data_ptr, const char*, const char* value, unsigned serial) {
  WaitForPropertyData* data = reinterpret_cast<WaitForPropertyData*>(data_ptr);
  if (*data->expected_value == value) {
    data->done = true;
  } else {
    data->last_read_serial = serial;
  }
}

// TODO: chrono_utils?
static void DurationToTimeSpec(timespec& ts, const std::chrono::milliseconds d) {
  auto s = std::chrono::duration_cast<std::chrono::seconds>(d);
  auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(d - s);
  ts.tv_sec = std::min<std::chrono::seconds::rep>(s.count(), std::numeric_limits<time_t>::max());
  ts.tv_nsec = ns.count();
}

// TODO: boot_clock?
using AbsTime = std::chrono::time_point<std::chrono::steady_clock>;

static void UpdateTimeSpec(timespec& ts, std::chrono::milliseconds relative_timeout,
                           const AbsTime& start_time) {
  auto now = std::chrono::steady_clock::now();
  auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
  if (time_elapsed >= relative_timeout) {
    ts = { 0, 0 };
  } else {
    auto remaining_timeout = relative_timeout - time_elapsed;
    DurationToTimeSpec(ts, remaining_timeout);
  }
}

// Waits for the system property `key` to be created.
// Times out after `relative_timeout`.
// Sets absolute_timeout which represents absolute time for the timeout.
// Returns nullptr on timeout.
static const prop_info* WaitForPropertyCreation(const std::string& key,
                                                const std::chrono::milliseconds& relative_timeout,
                                                const AbsTime& start_time) {
  // Find the property's prop_info*.
  const prop_info* pi;
  unsigned global_serial = 0;
  while ((pi = __system_property_find(key.c_str())) == nullptr) {
    // The property doesn't even exist yet.
    // Wait for a global change and then look again.
    timespec ts;
    UpdateTimeSpec(ts, relative_timeout, start_time);
    if (!__system_property_wait(nullptr, global_serial, &global_serial, &ts)) return nullptr;
  }
  return pi;
}

bool WaitForProperty(const std::string& key, const std::string& expected_value,
                     std::chrono::milliseconds relative_timeout) {
  auto start_time = std::chrono::steady_clock::now();
  const prop_info* pi = WaitForPropertyCreation(key, relative_timeout, start_time);
  if (pi == nullptr) return false;

  WaitForPropertyData data;
  data.expected_value = &expected_value;
  data.done = false;
  while (true) {
    timespec ts;
    // Check whether the property has the value we're looking for?
    __system_property_read_callback(pi, WaitForPropertyCallback, &data);
    if (data.done) return true;

    // It didn't, so wait for the property to change before checking again.
    UpdateTimeSpec(ts, relative_timeout, start_time);
    uint32_t unused;
    if (!__system_property_wait(pi, data.last_read_serial, &unused, &ts)) return false;
  }
}

bool WaitForPropertyCreation(const std::string& key,
                             std::chrono::milliseconds relative_timeout) {
  auto start_time = std::chrono::steady_clock::now();
  return (WaitForPropertyCreation(key, relative_timeout, start_time) != nullptr);
}

#endif

}  // namespace base
}  // namespace android
