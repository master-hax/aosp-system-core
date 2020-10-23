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

#if defined(__ANDROID__)

#include <unistd.h>

#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/thread_annotations.h>
#include <gtest/gtest.h>

using namespace std::chrono_literals;

struct PropertyChanges {
    std::unordered_map<std::string, std::vector<std::string>> changes GUARDED_BY(mutex);
    std::mutex mutex;
};

// PropertyMonitor cannot be destroyed: this helper leaks a new one, along with an output object.
// Real code is expected to use [[clang::no_destroy]] when declaring PropertyMonitor as a global.
std::pair<PropertyMonitor*, PropertyChanges*> LeakPropertyMonitor() {
    return {new PropertyMonitor(), new PropertyChanges()};
}

static std::string ManglePropertyName(std::string name) {
    name.push_back('.');
    name.append(std::to_string(gettid()));
    return name;
}

static void RegisterCallback(PropertyMonitor* pm, PropertyChanges* output,
                             std::string property_name) {
    pm->Add(property_name, [output, property_name](std::string value) {
        std::lock_guard<std::mutex> lock(output->mutex);
        LOG(INFO) << property_name << " = " << value;
        output->changes[property_name].emplace_back(std::move(value));
    });
}

TEST(PropertyMonitorTest, initial) {
    auto [pm, output] = LeakPropertyMonitor();

    std::string foo = ManglePropertyName("debug.property_monitor_test.foo");
    std::string never_set = ManglePropertyName("debug.property_monitor_test.never_set");

    RegisterCallback(pm, output, foo);
    android::base::SetProperty(foo, "foo");

    RegisterCallback(pm, output, never_set);

    pm->Start();

    std::lock_guard<std::mutex> lock(output->mutex);
    ASSERT_EQ(2UL, output->changes.size());
    ASSERT_EQ(1UL, output->changes[foo].size());
    ASSERT_EQ("foo", output->changes[foo][0]);
    ASSERT_EQ("", output->changes[never_set][0]);
}

TEST(PropertyMonitorTest, change) {
    auto [pm, output] = LeakPropertyMonitor();

    std::string foo = ManglePropertyName("debug.property_monitor_test.foo");

    RegisterCallback(pm, output, foo);
    android::base::SetProperty(foo, "foo");

    pm->Start();

    {
        std::lock_guard<std::mutex> lock(output->mutex);
        ASSERT_EQ(1UL, output->changes.size());
        ASSERT_EQ(1UL, output->changes[foo].size());
        ASSERT_EQ("foo", output->changes[foo][0]);
    }

    android::base::SetProperty(foo, "bar");
    std::this_thread::sleep_for(100ms);

    {
        std::lock_guard<std::mutex> lock(output->mutex);
        ASSERT_EQ(1UL, output->changes.size());
        ASSERT_EQ(2UL, output->changes[foo].size());
        ASSERT_EQ("foo", output->changes[foo][0]);
        ASSERT_EQ("bar", output->changes[foo][1]);
    }
}

TEST(PropertyMonitorTest, multiple) {
    auto [pm, output] = LeakPropertyMonitor();

    std::string foo = ManglePropertyName("debug.property_monitor_test.foo");
    std::string bar = ManglePropertyName("debug.property_monitor_test.bar");

    RegisterCallback(pm, output, foo);
    RegisterCallback(pm, output, bar);

    android::base::SetProperty(foo, "foo");
    android::base::SetProperty(bar, "bar");

    pm->Start();

    {
        std::lock_guard<std::mutex> lock(output->mutex);
        ASSERT_EQ(2UL, output->changes.size());

        ASSERT_EQ(1UL, output->changes[foo].size());
        ASSERT_EQ("foo", output->changes[foo][0]);

        ASSERT_EQ(1UL, output->changes[bar].size());
        ASSERT_EQ("bar", output->changes[bar][0]);
    }

    android::base::SetProperty(foo, "bar");
    android::base::SetProperty(bar, "foo");
    std::this_thread::sleep_for(100ms);

    {
        std::lock_guard<std::mutex> lock(output->mutex);
        ASSERT_EQ(2UL, output->changes.size());

        ASSERT_EQ(2UL, output->changes[foo].size());
        ASSERT_EQ("foo", output->changes[foo][0]);
        ASSERT_EQ("bar", output->changes[foo][1]);

        ASSERT_EQ(2UL, output->changes[bar].size());
        ASSERT_EQ("bar", output->changes[bar][0]);
        ASSERT_EQ("foo", output->changes[bar][1]);
    }
}

#endif  // defined(__ANDROID__)
