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

#define LOG_TAG "healthd-recovery"

#include <errno.h>
#include <string.h>

#include <string>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <cutils/klog.h>

#include "healthd.h"

using namespace android;

static const std::string BATTERY_INFO_PATH = "/tmp/battery_info";
static size_t count = 0;

void healthd_mode_recovery_battery_update(struct BatteryProperties *props) {
    std::string info = android::base::StringPrintf("battery l=%d v=%d t=%s%d.%d h=%d st=%d chg=%s%s%s\n",
                                                   props->batteryLevel, props->batteryVoltage,
                                                   props->batteryTemperature < 0 ? "-" : "",
                                                   abs(props->batteryTemperature / 10),
                                                   abs(props->batteryTemperature % 10),
                                                   props->batteryHealth,
                                                   props->batteryStatus,
                                                   props->chargerAcOnline ? "a" : "",
                                                   props->chargerUsbOnline ? "u" : "",
                                                   props->chargerWirelessOnline ? "w" : "");
    std::string tmp_file = BATTERY_INFO_PATH + ".tmp";
    if (!android::base::WriteStringToFile(info, tmp_file)) {
        KLOG_ERROR(LOG_TAG, "failed to write file %s: %s", tmp_file.c_str(), strerror(errno));
        return;
    }
    if (rename(tmp_file.c_str(), BATTERY_INFO_PATH.c_str()) == -1) {
        KLOG_ERROR(LOG_TAG, "failed to rename file %s to %s: %s\n", tmp_file.c_str(),
                   BATTERY_INFO_PATH.c_str(), strerror(errno));
        return;
    }
}
