/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "property_monitor.h"

#include <atomic>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <android-base/logging.h>

#if defined(__ANDROID__)
static uint32_t WaitForSerialChange(uint32_t current_serial) {
    uint32_t result;
    __system_property_wait(nullptr, current_serial, &result, nullptr);
    return result;
}

static bool FindProperty(const std::string& property_name, PropertyMonitorData* data) {
    const prop_info* p = __system_property_find(property_name.c_str());
    if (!p) {
        return false;
    }

    data->prop_info = p;
    return true;
}

// Read a property and return its value if it's been changed, while updating our cached serial.
static std::optional<std::string> ReadProperty(PropertyMonitorData* data) {
    struct ReadData {
        std::string value;
        uint32_t serial;
    };

    ReadData result;
    __system_property_read_callback(
            data->prop_info,
            [](void* cookie, const char* name, const char* value, uint32_t serial) {
                ReadData* result = static_cast<ReadData*>(cookie);
                result->value = value;
                result->serial = serial;
            },
            &result);

    if (result.serial <= data->serial) {
        return {};
    }

    data->serial = result.serial;
    return result.value;
}

#else

static uint32_t WaitForSerialChange(uint32_t current_serial) {
    if (current_serial == 0) {
        return 1;
    }

    pause();
}

static bool FindProperty(const std::string& property_name, PropertyMonitorData* data) {
    return false;
}

static std::optional<std::string> ReadProperty(PropertyMonitorData* data) {
    return {};
}

#endif

void PropertyMonitor::Add(std::string property, std::function<PropertyMonitorCallback> callback) {
    if (started_) {
        LOG(FATAL) << "PropertyMonitor::Add called while already started";
    }

    PropertyMonitorData data = {
            .callback = std::move(callback),
            .prop_info = nullptr,
            .serial = 0,
    };

    properties_.emplace_back(std::move(property), std::move(data));
}

void PropertyMonitor::Start() {
    std::thread([this]() { this->Run(); }).detach();

    std::unique_lock<std::mutex> lock(start_mutex_);
    start_cv_.wait(lock, [this]() { return started_.load(); });
}

void PropertyMonitor::Run() {
    // First, loop through all of our properties, and call the callbacks once.
    uint32_t current_serial = WaitForSerialChange(0);

    for (auto& [property_name, data] : properties_) {
        if (FindProperty(property_name, &data)) {
            data.callback(ReadProperty(&data).value());
        } else {
            data.callback(std::string());
        }
    }

    if (started_.exchange(true)) {
        LOG(FATAL) << "PropertyMonitor::Start called multiple times";
    }

    start_cv_.notify_one();

    while (true) {
        current_serial = WaitForSerialChange(current_serial);
        for (auto& [property_name, data] : properties_) {
            if (!data.prop_info) {
                if (FindProperty(property_name, &data)) {
                    data.callback(ReadProperty(&data).value());
                }
            } else {
                if (auto value = ReadProperty(&data); value) {
                    data.callback(value.value());
                }
            }
        }
    }
}
