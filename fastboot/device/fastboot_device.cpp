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
#include <android/hardware/boot/1.0/IBootControl.h>

#include "constants.h"
#include "flashing.h"
#include "usb_client.h"

using ::android::hardware::hidl_string;
using ::android::hardware::boot::V1_0::Slot;
namespace sph = std::placeholders;

FastbootDevice::FastbootDevice()
    : transport(std::make_unique<ClientUsbTransport>()),
      boot_control_module_(IBootControl::getService()),
      command_map({
              {std::string(FB_CMD_GETVAR), std::bind(GetVarHandler, sph::_1, sph::_2, sph::_3)},
              {std::string(FB_CMD_ERASE), std::bind(EraseHandler, sph::_1, sph::_2, sph::_3)},
              {std::string(FB_CMD_FLASH), std::bind(FlashHandler, sph::_1, sph::_2, sph::_3)},
              {std::string(FB_CMD_SET_ACTIVE),
               std::bind(SetActiveHandler, sph::_1, sph::_2, sph::_3)},
              {std::string(FB_CMD_DOWNLOAD), DownloadHandler},
              {std::string(FB_CMD_SHUTDOWN), std::bind(ShutDownHandler, sph::_1, sph::_3)},
              {std::string(FB_CMD_REBOOT), std::bind(RebootHandler, sph::_1, sph::_3)},
              {std::string(FB_CMD_REBOOT_BOOTLOADER),
               std::bind(RebootBootloaderHandler, sph::_1, sph::_3)},
              {std::string(FB_CMD_REBOOT_FASTBOOT),
               std::bind(RebootFastbootHandler, sph::_1, sph::_3)},
              {std::string(FB_CMD_REBOOT_RECOVERY),
               std::bind(RebootRecoveryHandler, sph::_1, sph::_3)},
      }),
      variables_map({
              {std::string(FB_VAR_VERSION), std::bind(GetVersion)},
              {std::string(FB_VAR_VERSION_BOOTLOADER), std::bind(GetBootloaderVersion)},
              {std::string(FB_VAR_VERSION_BASEBAND), std::bind(GetBasebandVersion)},
              {std::string(FB_VAR_PRODUCT), std::bind(GetProduct)},
              {std::string(FB_VAR_SERIALNO), std::bind(GetSerial)},
              {std::string(FB_VAR_SECURE), std::bind(GetSecure)},
              {std::string(FB_VAR_UNLOCKED), std::bind(GetUnlocked)},
              {std::string(FB_VAR_MAX_DOWNLOAD_SIZE), std::bind(GetMaxDownloadSize, sph::_1)},
              {std::string(FB_VAR_CURRENT_SLOT), std::bind(::GetCurrentSlot, sph::_1)},
              {std::string(FB_VAR_SLOT_COUNT), std::bind(GetSlotCount, sph::_1)},
              {std::string(FB_VAR_HAS_SLOT), GetHasSlot},
              {std::string(FB_VAR_PARTITION_SIZE), GetPartitionSize},
      }) {}

FastbootDevice::~FastbootDevice() {
    CloseDevice();
}

void FastbootDevice::CloseDevice() {
    if (flash_thread.valid()) {
        int ret = flash_thread.get();
        if (ret < 0) {
            LOG(ERROR) << "Last flash returned error " << ret;
        }
    }
    transport->Close();
}

bool FastbootDevice::OpenPartition(const std::string& name, PartitionHandle* handle) {
    std::function<void()> closer;
    std::optional<std::string> path = FindPhysicalPartition(name);
    if (!path) {
        LOG(ERROR) << "No such partition: " << name;
        return false;
    }

    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(path->c_str(), O_WRONLY | O_EXCL)));
    if (fd < 0) {
        PLOG(ERROR) << "Failed to open partition: " << path->c_str();
        return false;
    }

    *handle = PartitionHandle(std::move(fd), std::move(closer));
    return true;
}

int FastbootDevice::Flash(const std::string& name) {
    if (flash_thread.valid()) {
        int ret = flash_thread.get();
        if (ret < 0) {
            return ret;
        }
    }

    PartitionHandle handle;
    if (!OpenPartition(name, &handle)) {
        return -ENOENT;
    }

    if (GetDownloadData().size() == 0) {
        return -EINVAL;
    } else if (GetDownloadData().size() > get_block_device_size(handle.fd())) {
        return -EOVERFLOW;
    }
    flash_thread =
            std::async([handle(std::move(handle)), data(std::move(download_data))]() mutable {
                return FlashBlockDevice(handle.fd(), data);
            });
    return 0;
}

std::optional<std::string> FastbootDevice::GetVariable(const std::string& name,
                                                       const std::vector<std::string>& args) {
    if (variables_map.count(name) == 0) {
        return {};
    }
    return variables_map.at(name)(this, args);
}

std::string FastbootDevice::GetCurrentSlot() {
    // Non-A/B devices may not have boot control HALs.
    if (!boot_control_module_) {
        return "";
    }
    std::string suffix;
    auto cb = [&suffix](hidl_string s) { suffix = s; };
    boot_control_module_->getSuffix(boot_control_module_->getCurrentSlot(), cb);
    return suffix;
}

void FastbootDevice::ExecuteCommands() {
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
        int write_ret = this->GetTransport()->Write(buf, response_len);
        if (write_ret != response_len) {
            PLOG(ERROR) << "Failed to write " << message;
            ret = -1;
        }
    };

    auto handle_data = [this, &ret](std::vector<char>& data, bool read) {
        if (ret == -1) return false;
        auto read_write_data_size = read ? this->GetTransport()->Read(data.data(), data.size())
                                         : this->GetTransport()->Write(data.data(), data.size());
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
        command_map.at(args[0])(this, GetSubArgs(args), write_status, handle_data);
    }
}
