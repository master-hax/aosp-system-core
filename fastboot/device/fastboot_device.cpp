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

#include "fastboot_device.h"

#include <android-base/logging.h>
#include <android-base/strings.h>

#include "constants.h"
#include "usb_client.h"

namespace sph = std::placeholders;

FastbootDevice::FastbootDevice()
    : transport(std::make_unique<ClientUsbTransport>()),
      command_map({
              {std::string(FB_CMD_SET_ACTIVE),
               std::bind(set_active_handler, sph::_1, sph::_2, sph::_3)},
              {std::string(FB_CMD_DOWNLOAD), download_handler},
              {std::string(FB_CMD_SHUTDOWN), std::bind(shutdown_handler, sph::_1, sph::_3)},
              {std::string(FB_CMD_REBOOT), std::bind(reboot_handler, sph::_1, sph::_3)},
              {std::string(FB_CMD_REBOOT_BOOTLOADER),
               std::bind(reboot_bootloader_handler, sph::_1, sph::_3)},
              {std::string(FB_CMD_REBOOT_FASTBOOT),
               std::bind(reboot_fastboot_handler, sph::_1, sph::_3)},
              {std::string(FB_CMD_REBOOT_RECOVERY),
               std::bind(reboot_recovery_handler, sph::_1, sph::_3)},
      }) {}

FastbootDevice::~FastbootDevice() {
    close_device();
}

void FastbootDevice::close_device() {
    transport->Close();
}

void FastbootDevice::execute_commands() {
    char command[FB_RESPONSE_SZ + 1];
    char buf[FB_RESPONSE_SZ];
    int ret = 0;
    constexpr size_t response_reason_size = 4;
    constexpr size_t max_message_size = 60;
    constexpr size_t num_response_types = 4;  // "FAIL", "OKAY", "INFO", "DATA"

    auto write_status = [this, &ret, &buf](FastbootResult result, std::string message) {
        int msg_len = std::min(static_cast<unsigned long>(max_message_size), message.size());

        static const char* result_strs[num_response_types] = {RESPONSE_OKAY, RESPONSE_FAIL,
                                                              RESPONSE_INFO, RESPONSE_DATA};

        if (ret == -1) return;
        if (static_cast<size_t>(result) >= num_response_types) {
            ret = -1;
            return;
        }

        memcpy(reinterpret_cast<void*>(buf), result_strs[static_cast<int>(result)],
               response_reason_size);
        memcpy(reinterpret_cast<void*>(buf + response_reason_size), message.c_str(), msg_len);

        int response_len = response_reason_size + msg_len;
        int write_ret = this->get_transport()->Write(buf, response_len);
        if (write_ret != response_len) {
            PLOG(ERROR) << "Failed to write " << message;
            ret = -1;
        }
    };

    auto handle_data = [this, &ret](std::vector<char>& data, bool read) {
        if (ret == -1) return false;
        auto read_write_data_size = read ? this->get_transport()->Read(data.data(), data.size())
                                         : this->get_transport()->Write(data.data(), data.size());
        if (read_write_data_size != static_cast<ssize_t>(data.size())) {
            PLOG(ERROR) << "Error processing data " << ret << " " << data.size();
            ret = -1;
        }
        return read_write_data_size == static_cast<ssize_t>(data.size());
    };

    while (ret == 0) {
        auto thisret = transport->Read(command, FB_RESPONSE_SZ);
        if (thisret < 0) {
            PLOG(ERROR) << "Couldn't read command";
            return;
        }
        command[thisret] = '\0';

        LOG(INFO) << "Fastboot command: " << command;
        auto args = android::base::Split(std::string(command), ":");
        if (command_map.count(args[0]) == 0) {
            write_status(FastbootResult::FAIL, "Unrecognized command");
            continue;
        }
        command_map.at(args[0])(this, getSubArgs(args), write_status, handle_data);
    }
}
