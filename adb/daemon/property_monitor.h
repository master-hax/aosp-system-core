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

#pragma once

#include <sys/system_properties.h>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

using PropertyMonitorCallback = void(std::string value);

struct PropertyMonitorData {
    std::function<PropertyMonitorCallback> callback;
    const prop_info* prop_info;
    uint32_t serial;
};

struct PropertyMonitor {
    PropertyMonitor() = default;

    // PropertyMonitor cannot be stopped.
    ~PropertyMonitor() = delete;

    // Register a callback on a specified property.
    // Multiple callbacks can be registered on the same property.
    void Add(std::string property, std::function<PropertyMonitorCallback> callback);

    // Start the PropertyMonitor.
    // This will call each callback immediately with either the current value of the property or
    // the empty string if not defined yet. PropertyMonitor guarantees that each callback will be
    // called at least once before Start returns.
    void Start();

  private:
    void Run();

    std::vector<std::pair<std::string, PropertyMonitorData>> properties_;

    std::mutex start_mutex_;
    std::condition_variable start_cv_;
    std::atomic<bool> started_ = false;
};
