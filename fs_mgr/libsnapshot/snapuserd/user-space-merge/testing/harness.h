// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <stddef.h>
#include <sys/types.h>

#include <memory>

#include <snapuserd/block_server.h>

namespace android {
namespace snapshot {

class IUserDeviceFd {
  public:
    virtual ~IUserDeviceFd() {}
    virtual bool ReadFullyAtOffset(void* buffer, size_t size, off_t offset) = 0;
};

class IUserDevice {
  public:
    virtual ~IUserDevice() {}
    virtual std::unique_ptr<IUserDeviceFd> OpenFd() = 0;
    virtual bool Destroy() = 0;
};

class ITestHarness {
  public:
    virtual ~ITestHarness() {}
    virtual std::unique_ptr<IUserDevice> CreateDevice(const std::string& dev_name,
                                                      const std::string& misc_name,
                                                      uint64_t num_sectors) = 0;
    virtual IBlockServerFactory* GetBlockServerFactory() = 0;
};

}  // namespace snapshot
}  // namespace android
