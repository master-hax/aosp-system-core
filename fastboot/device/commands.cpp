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

#include "commands.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/android_reboot.h>
#include <ext4_utils/wipe.h>

#include "fastboot_device.h"
#include "flashing.h"

using ::android::hardware::hidl_string;
using ::android::hardware::boot::V1_0::BoolResult;
using ::android::hardware::boot::V1_0::CommandResult;
using ::android::hardware::boot::V1_0::Slot;

void getvar_handler(FastbootDevice* device, const std::vector<std::string>& args,
                    status_cb_t status_cb) {
    auto result = device->get_variable(getArg(args), getSubArgs(args));
    if (result) {
        status_cb(FastbootResult::OKAY, *result);
    } else {
        status_cb(FastbootResult::FAIL, "Unknown variable");
    }
}

void erase_handler(FastbootDevice* device, const std::vector<std::string>& args,
                   status_cb_t status_cb) {
    LOG(ERROR) << "Handling erase";
    int fd = device->get_block_device(getArg(args));
    if (fd < 0) {
        status_cb(FastbootResult::FAIL, "Partition doesn't exist");
    } else {
        if (wipe_block_device(fd, get_block_device_size(fd)) == 0) {
            status_cb(FastbootResult::OKAY, "Erasing succeeded");
        } else {
            status_cb(FastbootResult::FAIL, "Erasing failed");
        }
    }
}

void download_handler(FastbootDevice* device, const std::vector<std::string>& args,
                      status_cb_t status_cb, data_cb_t data_cb) {
    unsigned int size = strtoul(getArg(args).c_str(), nullptr, 16);
    if (size == 0 || size > 0xFFFFFFFF) {
        status_cb(FastbootResult::FAIL, "Invalid size");
        return;
    }
    LOG(ERROR) << "downloading " << size << " of fastboot data";
    device->get_download_data().resize(size);
    status_cb(FastbootResult::DATA, android::base::StringPrintf("%08x", size));

    if (data_cb(device->get_download_data(), true)) {
        status_cb(FastbootResult::OKAY, "");
    } else {
        LOG(ERROR) << "Couldn't download data";
        status_cb(FastbootResult::FAIL, "Couldn't download data");
    }
}

void flash_handler(FastbootDevice* device, const std::vector<std::string>& args,
                   status_cb_t status_cb) {
    int ret = device->flash(getArg(args));
    if (ret < 0) {
        status_cb(FastbootResult::FAIL, strerror(-ret));
    } else {
        status_cb(FastbootResult::OKAY, "Flashing succeeded");
    }
}

void set_active_handler(FastbootDevice* device, const std::vector<std::string>& args,
                        status_cb_t status_cb) {
    std::string arg = getArg(args);
    if (arg.size() != 1) {
        status_cb(FastbootResult::FAIL, "Invalid slot");
        return;
    }
    Slot slot = arg[0] - 'a';
    if (slot >= device->get_boot_control()->getNumberSlots()) {
        status_cb(FastbootResult::FAIL, "Slot out of range");
        return;
    }
    auto cb = [](CommandResult error) {};
    device->get_boot_control()->setActiveBootSlot(slot, cb);
    status_cb(FastbootResult::OKAY, "");
}

void shutdown_handler(FastbootDevice* device, status_cb_t status_cb) {
    status_cb(FastbootResult::OKAY, "Shutting down");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "shutdown,");
    device->close_device();
    TEMP_FAILURE_RETRY(pause());
}

void reboot_handler(FastbootDevice* device, status_cb_t status_cb) {
    status_cb(FastbootResult::OKAY, "Rebooting");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot");
    device->close_device();
    TEMP_FAILURE_RETRY(pause());
}

void reboot_bootloader_handler(FastbootDevice* device, status_cb_t status_cb) {
    status_cb(FastbootResult::OKAY, "Rebooting bootloader");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,bootloader");
    device->close_device();
    TEMP_FAILURE_RETRY(pause());
}

void reboot_fastboot_handler(FastbootDevice* device, status_cb_t status_cb) {
    status_cb(FastbootResult::OKAY, "Rebooting fastboot");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,fastboot");
    device->close_device();
    TEMP_FAILURE_RETRY(pause());
}

static void enter_recovery() {
    struct sockaddr_un addr;
    const char msg = 'r';
    android::base::unique_fd sock(socket(AF_UNIX, SOCK_STREAM, 0));
    if (sock < 0) {
        PLOG(ERROR) << "Couldn't create sock";
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/dev/socket/recovery", sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        PLOG(ERROR) << "Couldn't connect to recovery";
        return;
    }
    int ret = write(sock, &msg, sizeof(msg));
    if (ret != sizeof(msg)) {
        PLOG(ERROR) << "Couldn't write msg";
    }
}

void reboot_recovery_handler(FastbootDevice* device, status_cb_t status_cb) {
    status_cb(FastbootResult::OKAY, "Rebooting recovery");
    enter_recovery();
    device->close_device();
    TEMP_FAILURE_RETRY(pause());
}
