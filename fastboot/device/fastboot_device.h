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

#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>

#include "commands.h"
#include "transport.h"
#include "variables.h"

class FastbootDevice;

inline const std::vector<std::string> GetSubArgs(const std::vector<std::string>& v) {
    return v.size() > 1 ? std::vector<std::string>(v.begin() + 1, v.end())
                        : std::vector<std::string>();
}

inline std::string GetArg(const std::vector<std::string>& v) {
    return v.size() > 0 ? v[0] : "";
}

// Logical partitions are only mapped to a block device as needed, and
// immediately unmapped when no longer needed. In order to enforce this we
// require accessing partitions through a Handle abstraction, which may perform
// additional operations after closing its file description.
class PartitionHandle {
  public:
    PartitionHandle() {}
    PartitionHandle(android::base::unique_fd&& fd, std::function<void()>&& closer)
        : fd_(std::move(fd)), closer_(std::move(closer)) {}
    PartitionHandle(const PartitionHandle&) = delete;
    PartitionHandle(PartitionHandle&&) = default;
    PartitionHandle& operator=(const PartitionHandle&) = delete;
    PartitionHandle& operator=(PartitionHandle&&) = default;
    ~PartitionHandle() {
        if (closer_) {
            // Make sure the device is closed first.
            fd_ = {};
            closer_();
        }
    }
    int fd() const { return fd_.get(); }

  private:
    android::base::unique_fd fd_;
    std::function<void()> closer_;
};

class FastbootDevice {
  private:
    std::unique_ptr<Transport> transport;

    std::vector<char> download_data;
    std::vector<char> upload_data;

    const std::unordered_map<std::string, CommandHandler> command_map;
    const std::unordered_map<std::string, VariableHandler> variables_map;
    std::future<int> flash_thread;

  public:
    void CloseDevice();

    void ExecuteCommands();
    std::optional<std::string> GetVariable(const std::string& var,
                                           const std::vector<std::string>& args);

    bool OpenPartition(const std::string& name, PartitionHandle* handle);
    int Flash(const std::string& name);

    inline std::vector<char>& GetDownloadData() { return download_data; }

    inline void SetUploadData(const std::vector<char>& data) { upload_data = data; }

    inline Transport* GetTransport() { return transport.get(); }

    FastbootDevice();
    ~FastbootDevice();
};
