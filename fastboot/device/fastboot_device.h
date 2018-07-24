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
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <android-base/unique_fd.h>
#include <android/hardware/boot/1.0/IBootControl.h>
#include <ext4_utils/ext4_utils.h>

#include "commands.h"
#include "transport.h"
#include "variables.h"

// Logical partitions are only mapped to a block device as needed, and
// immediately unmapped when no longer needed. In order to enforce this we
// require accessing partitions through a Handle abstraction, which may perform
// additional operations after closing its file descriptor.
class PartitionHandle {
  public:
    PartitionHandle() {}
    explicit PartitionHandle(const std::string& path) : path_(path) {}
    PartitionHandle(const PartitionHandle&) = delete;
    PartitionHandle(PartitionHandle&&) = default;
    PartitionHandle& operator=(const PartitionHandle&) = delete;
    PartitionHandle& operator=(PartitionHandle&&) = default;
    const std::string& path() const { return path_; }
    int fd() const { return fd_.get(); }
    void set_fd(android::base::unique_fd&& fd) { fd_ = std::move(fd); }

  private:
    std::string path_;
    android::base::unique_fd fd_;
};

class FastbootDevice {
  public:
    FastbootDevice();
    ~FastbootDevice();

    void CloseDevice();
    void ExecuteCommands();
    bool WriteStatus(FastbootResult result, const std::string& message);
    bool HandleData(bool read, std::vector<char>* data);
    std::string GetCurrentSlot();
    bool OpenPartition(const std::string& name, PartitionHandle* handle);
    int Flash(const std::string& name);

    // Shortcuts for writing OKAY and FAIL status results.
    bool WriteOkay(const std::string& message);
    bool WriteFail(const std::string& message);

    std::vector<char>& get_download_data() { return download_data_; }
    void set_upload_data(const std::vector<char>& data) { upload_data_ = data; }
    void set_upload_data(std::vector<char>&& data) { upload_data_ = std::move(data); }
    Transport* get_transport() { return transport_.get(); }
    android::sp<android::hardware::boot::V1_0::IBootControl> boot_control_hal() {
        return boot_control_hal_;
    }

  private:
    bool OpenPhysicalPartition(const std::string& name, PartitionHandle* handle);

    const std::unordered_map<std::string, CommandHandler> kCommandMap;

    std::unique_ptr<Transport> transport_;
    android::sp<android::hardware::boot::V1_0::IBootControl> boot_control_hal_;
    std::vector<char> download_data_;
    std::vector<char> upload_data_;
    std::future<int> flash_thread_;
};
