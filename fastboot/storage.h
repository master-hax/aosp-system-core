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

#pragma once

#include <set>
#include <string>

#include "filesystem.h"

class ConnectedDevicesStorage {
  public:
    ConnectedDevicesStorage();
    void WriteDevices(const std::set<std::string>& devices);
    std::set<std::string> ReadDevices();
    void Clear();

    FileLock Lock() const;
  private:
    std::string devices_path_;
    std::string devices_lock_path_;
};