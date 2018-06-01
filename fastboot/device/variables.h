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
#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

class FastbootDevice;

using variable_handler =
        std::function<std::string(FastbootDevice*, const std::vector<std::string>&)>;

std::string get_version();
std::string get_bootloader_version();
std::string get_baseband_version();
std::string get_product();
std::string get_serial();
std::string get_secure();
std::string get_current_slot(FastbootDevice* device);
std::string get_slot_count(FastbootDevice* device);
std::string get_slot_successful(FastbootDevice* device, const std::vector<std::string>& args);
std::string get_partition_size(FastbootDevice* device, const std::vector<std::string>& args);
std::string get_max_download_size(FastbootDevice* device);
std::string get_unlocked();
std::string get_has_slot(const std::vector<std::string>& args);
std::string isOffModeChargeEnabled(FastbootDevice* device);
std::string isBatteryVoltageOk(FastbootDevice* device);
