/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "variables.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <ext4_utils/ext4_utils.h>
#include "fastboot_device.h"
#include "flashing.h"

using ::android::hardware::hidl_string;
using ::android::hardware::boot::V1_0::BoolResult;
using ::android::hardware::boot::V1_0::Slot;

#define POWER_SUPPLY_SYSFS_PATH "/sys/class/power_supply"

std::string get_version() {
    return ".4";
}

std::string get_bootloader_version() {
    return android::base::GetProperty("ro.bootloader", "");
}

std::string get_baseband_version() {
    return android::base::GetProperty("ro.build.expect.baseband", "");
}

std::string get_product() {
    return android::base::GetProperty("ro.product.name", "");
}

std::string get_serial() {
    return android::base::GetProperty("ro.serialno", "");
}

std::string get_secure() {
    return (android::base::GetProperty("ro.secure", "") == "1") ? "yes" : "no";
}

std::string get_current_slot(FastbootDevice* device) {
    std::string suffix;
    auto cb = [&suffix](hidl_string s) { suffix = s; };
    device->get_boot_control()->getSuffix(device->get_boot_control()->getCurrentSlot(), cb);
    return suffix.size() == 2 ? suffix.substr(1) : suffix;
}

std::string get_slot_count(FastbootDevice* device) {
    return std::to_string(device->get_boot_control()->getNumberSlots());
}

std::string get_slot_successful(FastbootDevice* device, const std::vector<std::string>& args) {
    Slot slot = std::stoi(getArg(args));
    return device->get_boot_control()->isSlotMarkedSuccessful(slot) == BoolResult::TRUE ? "yes"
                                                                                        : "no";
}

std::string get_max_download_size(FastbootDevice* device) {
    return std::to_string(device->get_fastboot_hal()->getMaxDownloadSize());
}

std::string get_unlocked() {
    return "yes";
}

std::string get_has_slot(const std::vector<std::string>& args) {
    std::string part = getArg(args);
    return part == "userdata" ? "no" : "yes";
}

std::string get_partition_size(FastbootDevice* device, const std::vector<std::string>& args) {
    int fd = device->get_block_device(getArg(args));
    if (fd < 0) {
        return "failed";
    }
    return std::to_string(get_block_device_size(fd));
}

std::string isOffModeChargeEnabled(FastbootDevice* device) {
    return device->get_fastboot_hal()->isOffModeChargeEnabled() ? "1" : "0";
}

//TODO: Use health HAL to get battery voltage once health 2.0 reaches AOSP.
bool getBatteryVoltage(int64_t* battery_voltage) {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(POWER_SUPPLY_SYSFS_PATH), closedir);
    if (!dir) {
        LOG(ERROR) << "Unable to get battery voltage";
        return false;
    }

    std::string type_path, type_value, voltage_path, voltage_value;
    dirent* dp;
    while ((dp = readdir(dir.get())) != nullptr) {
        if (dp->d_name[0] == '.') {
            continue;
        }
        type_path = android::base::StringPrintf("%s/%s/type", POWER_SUPPLY_SYSFS_PATH, dp->d_name);
        if (android::base::ReadFileToString(type_path, &type_value)) {
            type_value = android::base::Trim(type_value);
            /*
             * Power supply type strings are defined in
             * drivers/power/power_supply_sysfs.c
             */
            std::string type_battery = "Battery";
            if (type_value == type_battery) {
                voltage_path = android::base::StringPrintf("%s/%s/voltage_now",
                                                           POWER_SUPPLY_SYSFS_PATH, dp->d_name);
                if (android::base::ReadFileToString(voltage_path, &voltage_value)) {
                    *battery_voltage = std::stoi(voltage_value);
                    return true;
                }
            }
        }
    }
    LOG(ERROR) << "Unable to get battery voltage";
    return false;
}

std::string isBatteryVoltageOk(FastbootDevice* device) {
    int64_t battery_voltage = 0;
    bool result = getBatteryVoltage(&battery_voltage);
    if (!result)
        return "0";
    auto fastbootHal = device->get_fastboot_hal();
    int64_t voltageThreshold = fastbootHal->getBatteryVoltageFlashingThreshold();
    return battery_voltage >= voltageThreshold ? "1" : "0";
}
