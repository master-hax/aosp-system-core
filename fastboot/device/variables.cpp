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

constexpr int kMaxDownloadSizeDefault = 0x20000000;
constexpr float kFastbootProtocolVersion = .4;

std::string GetVersion() {
    return std::to_string(kFastbootProtocolVersion);
}

std::string GetBootloaderVersion() {
    return android::base::GetProperty("ro.bootloader", "");
}

std::string GetBasebandVersion() {
    return android::base::GetProperty("ro.build.expect.baseband", "");
}

std::string GetProduct() {
    return android::base::GetProperty("ro.product.device", "");
}

std::string GetSerial() {
    return android::base::GetProperty("ro.serialno", "");
}

std::string GetSecure() {
    return (android::base::GetProperty("ro.secure", "") == "1") ? "yes" : "no";
}

std::string GetCurrentSlot(FastbootDevice* device) {
    std::string suffix;
    auto boot_control_hal = device->get_boot_control();
    /*
     * Non-A/B devices may not have boot control HALs.
     */
    if (!boot_control_hal) {
        return "";
    }
    auto cb = [&suffix](hidl_string s) { suffix = s; };
    boot_control_hal->getSuffix(boot_control_hal->getCurrentSlot(), cb);
    return suffix.size() == 2 ? suffix.substr(1) : suffix;
}

std::string GetSlotCount(FastbootDevice* device) {
    auto boot_control_hal = device->get_boot_control();
    if (!boot_control_hal) {
        return "0";
    }
    return std::to_string(boot_control_hal->getNumberSlots());
}

std::string GetSlotSuccessful(FastbootDevice* device, const std::vector<std::string>& args) {
    auto boot_control_hal = device->get_boot_control();
    if (!boot_control_hal) {
        return "yes";
    }
    Slot slot = std::stoi(GetArg(args));
    return boot_control_hal->isSlotMarkedSuccessful(slot) == BoolResult::TRUE ? "yes" : "no";
}

std::string GetMaxDownloadSize(FastbootDevice* device) {
    return std::to_string(kMaxDownloadSizeDefault);
}

std::string GetUnlocked() {
    return "yes";
}

std::string GetHasSlot(FastbootDevice* device, const std::vector<std::string>& args) {
    std::string part = GetArg(args);
    std::string suffix = GetCurrentSlot(device);
    if (!suffix.empty()) {
        std::string part_with_suffix = part + "_" + suffix;
        if (PartitionExists(part_with_suffix)) {
            return "yes";
        }
    }
    return "no";
}

std::string GetPartitionSize(FastbootDevice* device, const std::vector<std::string>& args) {
    PartitionHandle handle;
    if (!device->OpenPartition(GetArg(args), &handle)) {
        return "failed";
    }
    return std::to_string(get_block_device_size(handle.fd()));
}
