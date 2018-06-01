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

#include <future>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <android/hardware/boot/1.0/IBootControl.h>
#include <android/hardware/fastboot/1.0/IFastboot.h>
#include <ext4_utils/ext4_utils.h>

#include "commands.h"
#include "transport.h"
#include "variables.h"

class FastbootDevice;

using android::hardware::boot::V1_0::IBootControl;
using android::hardware::fastboot::V1_0::IFastboot;

using android::sp;

inline const std::vector<std::string> getSubArgs(const std::vector<std::string>& v) {
    return v.size() > 1 ? std::vector<std::string>(v.begin() + 1, v.end())
                        : std::vector<std::string>();
}

inline std::string getArg(const std::vector<std::string>& v) {
    return v.size() > 0 ? v[0] : "";
}

class FastbootDevice {
  private:
    std::unique_ptr<Transport> transport;

    std::unordered_map<std::string, int> block_dev_map;

    sp<IBootControl> boot_control_module;
    sp<IFastboot> fastbootHal;

    std::vector<char> download_data;
    std::vector<char> upload_data;

    std::future<int> flash_thread;

    const std::unordered_map<std::string, command_handler> command_map;
    const std::unordered_map<std::string, variable_handler> variables_map;

  public:
    void close_device();
    int get_block_device(std::string name);

    sp<IBootControl> get_boot_control();
    sp<IFastboot> get_fastboot_hal();

    int flash(std::string name);
    std::optional<std::string> get_variable(const std::string& var,
                                            const std::vector<std::string>& args);
    void execute_commands();

    inline std::vector<char>& get_download_data() { return download_data; }

    inline void set_upload_data(const std::vector<char>& data) { upload_data = data; }

    inline Transport* get_transport() { return transport.get(); }

    FastbootDevice();
    ~FastbootDevice();
};
