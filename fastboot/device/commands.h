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

#include <functional>
#include <string>
#include <vector>

class FastbootDevice;

enum class FastbootResult {
    OKAY,
    FAIL,
    INFO,
    DATA,
};

// Send the given status as 4 bytes along with an informative message.
using StatusCb = std::function<void(FastbootResult, std::string)>;
// Read or write the entirety of the given vector to the transport.
using DataCb = std::function<bool(std::vector<char>&, bool)>;

// Execute a command with the given arguments (possibly empty).
// The command is responsible for reporting its own status through status_cb,
// and can retrieve data through data_cb.
using CommandHandler =
        std::function<void(FastbootDevice*, const std::vector<std::string>&, StatusCb, DataCb)>;

void GetVarHandler(FastbootDevice* device, const std::vector<std::string>& args,
                   StatusCb status_cb);
void DownloadHandler(FastbootDevice* device, const std::vector<std::string>& args,
                     StatusCb status_cb, DataCb data_cb);
void SetActiveHandler(FastbootDevice* device, const std::vector<std::string>& args,
                      StatusCb status_cb);
void ShutDownHandler(FastbootDevice* device, StatusCb status_cb);
void RebootHandler(FastbootDevice* device, StatusCb status_cb);
void RebootBootloaderHandler(FastbootDevice* device, StatusCb status_cb);
void RebootFastbootHandler(FastbootDevice* device, StatusCb status_cb);
void RebootRecoveryHandler(FastbootDevice* device, StatusCb status_cb);
