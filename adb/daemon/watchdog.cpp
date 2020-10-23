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

#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <mutex>
#include <thread>

#include <android-base/logging.h>
#include <android-base/parsebool.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/thread_annotations.h>

#include "property_monitor.h"

static constexpr char kAdbWatchdogProperty[] = "persist.adb.watchdog";
static constexpr char kTestHarnessProperty[] = "persist.sys.test_harness";

static constexpr unsigned int kDefaultAdbWatchdogTimeoutSeconds = 600;
static unsigned int g_watchdog_timeout_seconds;

static std::mutex g_watchdog_mutex [[clang::no_destroy]];
static bool g_watchdog_enabled GUARDED_BY(g_watchdog_mutex) = false;
static bool g_watchdog_counting GUARDED_BY(g_watchdog_mutex) = false;

static PropertyMonitor g_property_monitor [[clang::no_destroy]];

static void ArmWatchdog() REQUIRES(g_watchdog_mutex) {
    static std::once_flag once;
    std::call_once(once, []() {
        signal(SIGALRM, [](int) {
            execl("/system/bin/reboot", "/system/bin/reboot", "bootloader", nullptr);
        });
    });

    LOG(INFO) << "adb watchdog armed, triggering in " << g_watchdog_timeout_seconds << " seconds";
    alarm(g_watchdog_timeout_seconds);
}

static void DisarmWatchdog() REQUIRES(g_watchdog_mutex) {
    unsigned int previous = alarm(0);
    if (previous != 0) {
        LOG(INFO) << "adb watchdog disarmed with " << previous << " seconds left";
    }
}

static bool ShouldWatchdogBeEnabled() {
    std::string explicit_setting = android::base::GetProperty(kAdbWatchdogProperty, "");

    // If it's non-empty, persist.adb.watchdog overrides persist.sys.test_harness.
    if (!explicit_setting.empty()) {
        return android::base::ParseBool(explicit_setting) == android::base::ParseBoolResult::kTrue;
    }

    // Otherwise, use whatever persist.sys.test_harness is set to.
    return android::base::GetBoolProperty(kTestHarnessProperty, false);
}

static void RefreshWatchdogStatus() EXCLUDES(g_watchdog_mutex) {
    bool should_enable = ShouldWatchdogBeEnabled();

    std::lock_guard<std::mutex> lock(g_watchdog_mutex);
    if (should_enable != g_watchdog_enabled) {
        if (should_enable) {
            LOG(INFO) << "enabling adb watchdog";
        } else {
            LOG(INFO) << "disabling adb watchdog";
        }

        // Arm/disarm the watchdog if needed.
        if (g_watchdog_counting) {
            if (should_enable) {
                ArmWatchdog();
            } else {
                DisarmWatchdog();
            }
        }

        g_watchdog_enabled = should_enable;
    }
}

namespace watchdog {

void Start() {
    std::lock_guard<std::mutex> lock(g_watchdog_mutex);

    if (g_watchdog_counting) {
        return;
    }
    g_watchdog_counting = true;

    if (!g_watchdog_enabled) {
        return;
    }
    ArmWatchdog();
}

void Stop() {
    std::lock_guard<std::mutex> lock(g_watchdog_mutex);
    if (g_watchdog_counting) {
        g_watchdog_counting = false;
        DisarmWatchdog();
    }
}

void Initialize() {
    for (auto& property : {kAdbWatchdogProperty, kTestHarnessProperty}) {
        g_property_monitor.Add(property, [property](std::string value) {
            LOG(INFO) << property << " set to '" << value << "'";
            RefreshWatchdogStatus();
        });
    }

    g_property_monitor.Add("persist.adb.watchdog.timeout_secs", [](std::string value) {
        // This presumably isn't going to change while the watchdog is armed,
        // so we don't need to recalculate a timer.
        {
            std::lock_guard<std::mutex> lock(g_watchdog_mutex);
            if (!android::base::ParseUint(value, &g_watchdog_timeout_seconds)) {
                g_watchdog_timeout_seconds = kDefaultAdbWatchdogTimeoutSeconds;
            }
        }

        LOG(INFO) << "adb watchdog timeout set to " << g_watchdog_timeout_seconds << " seconds";
    });

    g_property_monitor.Start();
    Start();
}

}  // namespace watchdog
