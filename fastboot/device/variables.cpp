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
    std::string suffix = device->GetCurrentSlot();
    return suffix.size() == 2 ? suffix.substr(1) : suffix;
}

std::string GetSlotCount(FastbootDevice* device) {
    auto boot_control_hal = device->boot_control_module();
    if (!boot_control_hal) {
        return "0";
    }
    return std::to_string(boot_control_hal->getNumberSlots());
}

std::string GetSlotSuccessful(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 1) {
        return "no";
    }
    Slot slot;
    if (!device->GetSlotNumber(args[0], &slot)) {
        return "no";
    }
    auto boot_control_hal = device->boot_control_module();
    if (!boot_control_hal) {
        return "no";
    }
    return boot_control_hal->isSlotMarkedSuccessful(slot) == BoolResult::TRUE ? "yes" : "no";
}

std::string GetSlotUnbootable(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 1) {
        return "no";
    }
    Slot slot;
    if (!device->GetSlotNumber(args[0], &slot)) {
        return "no";
    }
    auto boot_control_hal = device->boot_control_module();
    if (!boot_control_hal) {
        return "no";
    }
    return boot_control_hal->isSlotBootable(slot) == BoolResult::TRUE ? "no" : "yes";
}

std::string GetMaxDownloadSize() {
    return std::to_string(kMaxDownloadSizeDefault);
}

std::string GetUnlocked() {
    return "yes";
}

std::string GetHasSlot(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 1) {
        return "no";
    }
    std::string slot_suffix = device->GetCurrentSlot();
    if (slot_suffix.empty()) {
        return "no";
    }
    return args[0] == "userdata" ? "no" : "yes";
}

std::string GetPartitionSize(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 1) {
        return "failed";
    }
    PartitionHandle handle;
    if (!device->OpenPartition(args[0], &handle)) {
        return "failed";
    }
    return std::to_string(get_block_device_size(handle.fd()));
}
