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

#include <memory>
#include <unordered_map>

#include <android-base/unique_fd.h>

#include "harness.h"
#include "temp_device.h"

namespace android {
namespace snapshot {

class LocalBlockServerFactory;
class LocalBlockServerQueue;

class LocalUserDeviceFd final : public IUserDeviceFd {
  public:
    explicit LocalUserDeviceFd(std::shared_ptr<LocalBlockServerQueue> queue);

    bool ReadFullyAtOffset(void* buffer, size_t size, off_t offset) override;

  private:
    std::shared_ptr<LocalBlockServerQueue> queue_;
};

class LocalUserDevice final : public IUserDevice {
  public:
    explicit LocalUserDevice(std::shared_ptr<LocalBlockServerFactory> factory,
                             std::shared_ptr<LocalBlockServerQueue> queue);

    std::unique_ptr<IUserDeviceFd> OpenFd() override;
    virtual bool Destroy() override;

  private:
    std::shared_ptr<LocalBlockServerFactory> factory_;
    std::shared_ptr<LocalBlockServerQueue> queue_;
};

class LocalUserTestHarness final : public ITestHarness {
  public:
    LocalUserTestHarness();

    std::unique_ptr<IUserDevice> CreateDevice(const std::string& dev_name,
                                              const std::string& misc_name,
                                              uint64_t num_sectors) override;
    IBlockServerFactory* GetBlockServerFactory() override;

  private:
    std::shared_ptr<LocalBlockServerFactory> block_server_factory_;
};

}  // namespace snapshot
}  // namespace android
