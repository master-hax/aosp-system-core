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
#include <string>
#include <vector>

class FastbootDevice;

enum class FastbootResult {
    OKAY,
    FAIL,
    INFO,
    DATA,
};

// Send the given status as 4 bytes along with an informative message.
using status_cb_t = std::function<void(FastbootResult, std::string)>;
// Read or write the entirety of the given vector to the transport.
using data_cb_t = std::function<bool(std::vector<char>&, bool)>;

// Execute a command with the given arguments (possibly empty).
// The command is responsible for reporting its own status through status_cb,
// and can retrieve data through data_cb.
using command_handler =
        std::function<void(FastbootDevice*, const std::vector<std::string>&, status_cb_t, data_cb_t)>;

void getvar_handler(FastbootDevice* device, const std::vector<std::string>& args,
                    status_cb_t status_cb);
void erase_handler(FastbootDevice* device, const std::vector<std::string>& args,
                   status_cb_t status_cb);
void flash_handler(FastbootDevice* device, const std::vector<std::string>& args,
                   status_cb_t status_cb);
void download_handler(FastbootDevice* device, const std::vector<std::string>& args,
                      status_cb_t status_cb, data_cb_t data_cb);
void set_active_handler(FastbootDevice* device, const std::vector<std::string>& args,
                        status_cb_t status_cb);
void shutdown_handler(FastbootDevice* device, status_cb_t status_cb);
void reboot_handler(FastbootDevice* device, status_cb_t status_cb);
void reboot_bootloader_handler(FastbootDevice* device, status_cb_t status_cb);
void reboot_fastboot_handler(FastbootDevice* device, status_cb_t status_cb);
void reboot_recovery_handler(FastbootDevice* device, status_cb_t status_cb);
