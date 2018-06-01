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

#include <boot/BootControl.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <fastboot/Fastboot.h>

#include "constants.h"
#include "flashing.h"
#include "usb_client.h"

namespace sph = std::placeholders;

FastbootDevice::FastbootDevice()
    : transport(std::make_unique<ClientUsbTransport>()),
      boot_control_module(
              android::hardware::boot::V1_0::implementation::HIDL_FETCH_IBootControl("")),
      command_map({
              {std::string(FB_CMD_GETVAR), std::bind(getvar_handler, sph::_1, sph::_2, sph::_3)},
              {std::string(FB_CMD_ERASE), std::bind(erase_handler, sph::_1, sph::_2, sph::_3)},
              {std::string(FB_CMD_FLASH), std::bind(flash_handler, sph::_1, sph::_2, sph::_3)},
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
      }),
      variables_map({
              {std::string(FB_VAR_VERSION), std::bind(get_version)},
              {std::string(FB_VAR_VERSION_BOOTLOADER), std::bind(get_bootloader_version)},
              {std::string(FB_VAR_VERSION_BASEBAND), std::bind(get_baseband_version)},
              {std::string(FB_VAR_PRODUCT), std::bind(get_product)},
              {std::string(FB_VAR_SERIALNO), std::bind(get_serial)},
              {std::string(FB_VAR_SECURE), std::bind(get_secure)},
              {std::string(FB_VAR_UNLOCKED), std::bind(get_unlocked)},
              {std::string(FB_VAR_MAX_DOWNLOAD_SIZE), std::bind(get_max_download_size, sph::_1)},
              {std::string(FB_VAR_CURRENT_SLOT), std::bind(get_current_slot, sph::_1)},
              {std::string(FB_VAR_SLOT_COUNT), std::bind(get_slot_count, sph::_1)},
              {std::string(FB_VAR_HAS_SLOT), std::bind(get_has_slot, sph::_2)},
              {std::string(FB_VAR_PARTITION_SIZE), get_partition_size},
              {std::string(FB_OFF_MODE_CHARGE), std::bind(isOffModeChargeEnabled, sph::_1)},
              {std::string(FB_BATTERY_SOC_OK), std::bind(isBatteryVoltageOk, sph::_1)},
      }) {
    fastbootHal = android::hardware::fastboot::V1_0::implementation::Fastboot::getInstance();
}

FastbootDevice::~FastbootDevice() {
    close_device();
}

sp<IBootControl> FastbootDevice::get_boot_control() {
    return boot_control_module;
}

sp<IFastboot> FastbootDevice::get_fastboot_hal() {
    return fastbootHal;
}

void FastbootDevice::close_device() {
    if (flash_thread.valid()) {
        int ret = flash_thread.get();
        if (ret < 0) {
            LOG(ERROR) << "Last flash returned error " << ret;
        }
    }
    for (auto pair : block_dev_map) {
        close(pair.second);
    }
    block_dev_map.clear();
    transport->Close();
}

int FastbootDevice::get_block_device(std::string name) {
    if (block_dev_map.count(name) == 0) {
        int block_fd = get_partition_device(name);
        if (block_fd > 0) {
            block_dev_map[name] = block_fd;
        }
        return block_fd;
    }
    return block_dev_map[name];
}

int FastbootDevice::flash(std::string name) {
    if (flash_thread.valid()) {
        int ret = flash_thread.get();
        if (ret < 0) {
            return ret;
        }
    }
    int fd = get_block_device(name);
    if (fd < 0) {
        return -errno;
    } else if (get_download_data().size() == 0) {
        return -EINVAL;
    } else if (get_download_data().size() > get_block_device_size(fd)) {
        return -EOVERFLOW;
    }
    flash_thread = std::async([fd, data(std::move(download_data))]() mutable {
        return flash_block_device(fd, data);
    });
    return 0;
}

std::optional<std::string> FastbootDevice::get_variable(const std::string& name,
                                                        const std::vector<std::string>& args) {
    if (variables_map.count(name) == 0) {
        return {};
    }
    return variables_map.at(name)(this, args);
}

void FastbootDevice::execute_commands() {
    char command[FB_RESPONSE_SZ + 1];
    char buf[FB_RESPONSE_SZ];
    int ret = 0;

    auto write_status = [this, &ret, &buf](FastbootResult result, std::string message) {
        int msg_len = std::min((unsigned long)60, message.size());

        static const char* result_strs[] = {RESPONSE_OKAY, RESPONSE_FAIL, RESPONSE_INFO,
                                            RESPONSE_DATA};

        if (ret == -1) return;

        memcpy((void*)buf, result_strs[(int)result], 4);
        memcpy((void*)(buf + 4), message.c_str(), msg_len);

        ssize_t ret = this->get_transport()->Write(buf, 4 + msg_len);
        if (ret != 4 + msg_len) {
            PLOG(ERROR) << "Failed to write " << message;
            ret = -1;
        }
    };

    auto handle_data = [this, &ret](std::vector<char>& data, bool read) {
        if (ret == -1) return false;
        ssize_t r = read ? this->get_transport()->Read(data.data(), data.size())
                         : this->get_transport()->Write(data.data(), data.size());
        if (r != static_cast<ssize_t>(data.size())) {
            PLOG(ERROR) << "Error processing data " << ret << " " << data.size();
            ret = -1;
        }
        return r == static_cast<ssize_t>(data.size());
    };

    while (ret == 0) {
        ssize_t thisret = transport->Read(command, FB_RESPONSE_SZ);
        if (thisret < 0) {
            PLOG(ERROR) << "Couldn't read command";
            return;
        }
        command[thisret] = '\0';

        LOG(INFO) << "Fastboot command: " << command;
        std::vector<std::string> args = android::base::Split(std::string(command), ":");
        if (command_map.count(args[0]) == 0) {
            write_status(FastbootResult::FAIL, "Unrecognized command");
            continue;
        }
        command_map.at(args[0])(this, getSubArgs(args), write_status, handle_data);
    }
}
