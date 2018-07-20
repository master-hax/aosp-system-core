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
    return "";
}

std::string GetSlotCount(FastbootDevice* device) {
    return "0";
}

std::string GetSlotSuccesful(FastbootDevice* device, const std::vector<std::string>& args) {
    return "yes";
}

std::string GetMaxDownloadSize(FastbootDevice* device) {
    return "0x20000000";
}

std::string GetUnlocked() {
    return "yes";
}

std::string GetHasSlot(const std::vector<std::string>& args) {
    std::string part = GetArg(args);
    return part == "userdata" ? "no" : "yes";
}
