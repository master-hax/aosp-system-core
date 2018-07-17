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
    : transport_(std::make_unique<ClientUsbTransport>()),
      command_map_({
              {FB_CMD_SET_ACTIVE, std::bind(SetActiveHandler, sph::_1, sph::_2)},
              {FB_CMD_DOWNLOAD, DownloadHandler},
              {FB_CMD_SHUTDOWN, std::bind(ShutDownHandler, sph::_1)},
              {FB_CMD_REBOOT, std::bind(RebootHandler, sph::_1)},
              {FB_CMD_REBOOT_BOOTLOADER, std::bind(RebootBootloaderHandler, sph::_1)},
              {FB_CMD_REBOOT_FASTBOOT, std::bind(RebootFastbootHandler, sph::_1)},
              {FB_CMD_REBOOT_RECOVERY, std::bind(RebootRecoveryHandler, sph::_1)},
      }) {}

FastbootDevice::~FastbootDevice() {
    CloseDevice();
}

void FastbootDevice::CloseDevice() {
    transport_->Close();
}

bool FastbootDevice::WriteStatus(FastbootResult result, std::string message) {
    constexpr size_t response_reason_size = 4;
    constexpr size_t num_response_types = 4;  // "FAIL", "OKAY", "INFO", "DATA"
    char buf[FB_RESPONSE_SZ];
    constexpr size_t max_message_size = sizeof(buf) - response_reason_size;
    int msg_len = std::min(max_message_size, static_cast<size_t>(message.size()));

    static const char* result_strs[num_response_types] = {RESPONSE_OKAY, RESPONSE_FAIL,
                                                          RESPONSE_INFO, RESPONSE_DATA};

    if (static_cast<size_t>(result) >= num_response_types) {
        return false;
    }

    memcpy(reinterpret_cast<void*>(buf), result_strs[static_cast<int>(result)],
           response_reason_size);
    memcpy(reinterpret_cast<void*>(buf + response_reason_size), message.c_str(), msg_len);

    int response_len = response_reason_size + msg_len;
    int write_ret = this->GetTransport()->Write(buf, response_len);
    if (write_ret != response_len) {
        PLOG(ERROR) << "Failed to write " << message;
        return false;
    }

    return true;
}

bool FastbootDevice::HandleData(std::vector<char>& data, bool read) {
    auto read_write_data_size = read ? this->GetTransport()->Read(data.data(), data.size())
                                     : this->GetTransport()->Write(data.data(), data.size());
    if (read_write_data_size != static_cast<ssize_t>(data.size())) {
        return false;
    }
    return true;
}

void FastbootDevice::ExecuteCommands() {
    char command[FB_RESPONSE_SZ + 1];
    for (;;) {
        auto thisret = transport_->Read(command, FB_RESPONSE_SZ);
        if (thisret < 0) {
            PLOG(ERROR) << "Couldn't read command";
            return;
        }
        command[thisret] = '\0';

        PLOG(INFO) << "Fastboot command: " << command;
        auto args = android::base::Split(command, ":");
        auto found_command = command_map_.find(args[0]);
        if (found_command == command_map_.end()) {
            WriteStatus(FastbootResult::FAIL, "Unrecognized command");
            continue;
        }
        if (!command_map_.at(args[0])(this, args)) {
            return;
        }
    }
}
