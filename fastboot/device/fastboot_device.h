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

#include <ext4_utils/ext4_utils.h>

#include "commands.h"
#include "transport.h"

class FastbootDevice;

inline const std::vector<std::string> GetSubArgs(const std::vector<std::string>& v) {
    return v.size() > 1 ? std::vector<std::string>(v.begin() + 1, v.end())
                        : std::vector<std::string>();
}

inline std::string GetArg(const std::vector<std::string>& v) {
    return v.size() > 0 ? v[0] : "";
}

class FastbootDevice {
  private:
    std::unique_ptr<Transport> transport;

    std::vector<char> download_data;
    std::vector<char> upload_data;

    const std::unordered_map<std::string, command_handler> command_map;

  public:
    void CloseDevice();

    void ExecuteCommands();

    inline std::vector<char>& GetDownloadData() { return download_data; }

    inline void SetUploadData(const std::vector<char>& data) { upload_data = data; }

    inline Transport* GetTransport() { return transport.get(); }

    FastbootDevice();
    ~FastbootDevice();
};
