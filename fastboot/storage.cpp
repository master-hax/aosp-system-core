/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <fstream>

#include "storage.h"
#include "util.h"

ConnectedDevicesStorage::ConnectedDevicesStorage() {
    const std::string home_path = GetHomeDirPath();
    if (home_path.empty()) {
        return;
    }

    const std::string home_fastboot_path = home_path + kPathSeparator + ".fastboot";

    if (!EnsureDirectoryExists(home_fastboot_path)) {
        die("Cannot create $HOME/.fastboot directory");
    }

    devices_path_ = home_fastboot_path + kPathSeparator + "devices";
    devices_lock_path_ = home_fastboot_path + kPathSeparator + "devices.lock";
}

void ConnectedDevicesStorage::DumpDevices(const std::set<std::string>& devices) {
    std::ofstream devices_stream(devices_path_);
    std::copy(devices.begin(), devices.end(),
              std::ostream_iterator<std::string>(devices_stream, "\n"));
}

std::set<std::string> ConnectedDevicesStorage::ReadDevices() {
    std::ifstream devices_stream(devices_path_);
    std::istream_iterator<std::string> start(devices_stream), end;
    std::set<std::string> devices(start, end);
    return devices;
}

void ConnectedDevicesStorage::Clear() {
    if (!EnsureFileDoesntExist(devices_path_)) {
        die("Cannot disconnect the devices due to devices file delition problem");
    }
}

FileLock ConnectedDevicesStorage::Lock() const {
    return FileLock(devices_lock_path_);
}