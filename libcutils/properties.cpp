/*
 * Copyright (C) 2006 The Android Open Source Project
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

#include <cutils/properties.h>

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <android-base/properties.h>

int8_t property_get_bool(const char* key, int8_t default_value) {
    if (!key) return default_value;
    return android::base::GetBoolProperty(key, default_value);
}

template <typename T>
static T property_get_int(const char* key, T default_value) {
    std::string value = android::base::GetProperty(key, "");
    T result = default_value;
    if (!value.empty()) {
        // libcutils unwisely allows octal, which libbase doesn't.
        int saved_errno = errno;
        errno = 0;
        char* end = nullptr;
        intmax_t v = strtoimax(&value[0], &end, 0);
        if (errno != ERANGE && end != &value[0] && v >= std::numeric_limits<T>::min() &&
            v <= std::numeric_limits<T>::max()) {
            result = v;
        }
        errno = saved_errno;
    }
    return result;
}

int64_t property_get_int64(const char* key, int64_t default_value) {
    if (!key) return default_value;
    return property_get_int<int64_t>(key, default_value);
}

int32_t property_get_int32(const char* key, int32_t default_value) {
    if (!key) return default_value;
    return property_get_int<int32_t>(key, default_value);
}

int property_set(const char* key, const char* value) {
    if (key == nullptr) return -1;
    if (value == nullptr) value = "";
    return android::base::SetProperty(key, value) ? 0 : -1;
}

int property_get(const char* key, char* value, const char* default_value) {
    if (default_value == nullptr) default_value = "";
    std::string new_value = key ? android::base::GetProperty(key, default_value) : default_value;
    snprintf(value, PROPERTY_VALUE_MAX, "%s", new_value.c_str());
    return strlen(value);
}

#if __has_include(<sys/system_properties.h>)

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

struct callback_data {
    void (*callback)(const char* name, const char* value, void* cookie);
    void* cookie;
};

static void trampoline(void* raw_data, const char* name, const char* value, unsigned /*serial*/) {
    callback_data* data = reinterpret_cast<callback_data*>(raw_data);
    data->callback(name, value, data->cookie);
}

static void property_list_callback(const prop_info* pi, void* data) {
    __system_property_read_callback(pi, trampoline, data);
}

int property_list(void (*fn)(const char* name, const char* value, void* cookie), void* cookie) {
    callback_data data = {fn, cookie};
    return __system_property_foreach(property_list_callback, &data);
}

#endif
