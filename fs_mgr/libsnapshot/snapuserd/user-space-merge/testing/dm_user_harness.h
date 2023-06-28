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

#include <android-base/unique_fd.h>

#include "harness.h"
#include "temp_device.h"

namespace android {
namespace snapshot {

using android::base::unique_fd;

class DmUserBlockServerFactory;

class DmUserDeviceFd final : public IUserDeviceFd {
  public:
    explicit DmUserDeviceFd(unique_fd&& fd);

    bool ReadFullyAtOffset(void* buffer, size_t size, off_t offset) override;

  private:
    unique_fd fd_;
};

class DmUserDevice final : public IUserDevice {
  public:
    explicit DmUserDevice(std::unique_ptr<Tempdevice>&& dev);
    std::unique_ptr<IUserDeviceFd> OpenFd() override;
    virtual bool Destroy() override;

  private:
    std::unique_ptr<Tempdevice> dev_;
};

class DmUserTestHarness final : public ITestHarness {
  public:
    DmUserTestHarness();

    std::unique_ptr<IUserDevice> CreateDevice(const std::string& dev_name,
                                              const std::string& misc_name,
                                              uint64_t num_sectors) override;
    IBlockServerFactory* GetBlockServerFactory() override;

  private:
    std::unique_ptr<DmUserBlockServerFactory> block_server_factory_;
};

}  // namespace snapshot
}  // namespace android
