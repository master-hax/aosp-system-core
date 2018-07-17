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

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "commands.h"
#include "transport.h"

class FastbootDevice;

class FastbootDevice {
  public:
    void CloseDevice();

    void ExecuteCommands();

    std::vector<char>& GetDownloadData() { return download_data_; }

    void SetUploadData(const std::vector<char>& data) { upload_data_ = data; }
    void SetUploadData(std::vector<char>&& data) { upload_data_ = std::move(data); }

    Transport* GetTransport() { return transport_.get(); }

    bool WriteStatus(FastbootResult result, std::string message);
    bool HandleData(std::vector<char>& data, bool read);

    FastbootDevice();
    ~FastbootDevice();

  private:
    std::unique_ptr<Transport> transport_;

    std::vector<char> download_data_;
    std::vector<char> upload_data_;

    const std::unordered_map<std::string, CommandHandler> command_map_;
};
