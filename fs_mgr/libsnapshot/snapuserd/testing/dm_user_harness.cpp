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

#include "dm_user_harness.h"

#include <fcntl.h>

#include <android-base/file.h>
#include <fs_mgr/file_wait.h>
#include <libdm/dm.h>
#include <snapuserd/block_server_dm_user.h>

namespace android {
namespace snapshot {

using namespace std::chrono_literals;
using android::base::unique_fd;

DmUserDeviceFd::DmUserDeviceFd(unique_fd&& fd) : fd_(std::move(fd)) {}

bool DmUserDeviceFd::ReadFullyAtOffset(void* buffer, size_t size, off_t offset) {
    return android::base::ReadFullyAtOffset(fd_, buffer, size, offset);
}

DmUserDevice::DmUserDevice(std::unique_ptr<Tempdevice>&& dev) : dev_(std::move(dev)) {}

std::unique_ptr<IUserDeviceFd> DmUserDevice::OpenFd() {
    unique_fd fd(open(dev_->path().c_str(), O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        return nullptr;
    }
    return std::make_unique<DmUserDeviceFd>(std::move(fd));
}

bool DmUserDevice::Destroy() {
    return dev_->Destroy();
}

DmUserTestHarness::DmUserTestHarness() {
    block_server_factory_ = std::make_unique<DmUserBlockServerFactory>();
}

std::unique_ptr<IUserDevice> DmUserTestHarness::CreateDevice(const std::string& dev_name,
                                                             const std::string& misc_name,
                                                             uint64_t num_sectors) {
    android::dm::DmTable dmuser_table;
    dmuser_table.Emplace<android::dm::DmTargetUser>(0, num_sectors, misc_name);
    auto dev = std::make_unique<Tempdevice>(dev_name, dmuser_table);
    if (!dev->valid()) {
        return nullptr;
    }

    auto misc_device = "/dev/dm-user/" + misc_name;
    if (!android::fs_mgr::WaitForFile(misc_device, 10s)) {
        return nullptr;
    }

    return std::make_unique<DmUserDevice>(std::move(dev));
}

IBlockServerFactory* DmUserTestHarness::GetBlockServerFactory() {
    return block_server_factory_.get();
}

}  // namespace snapshot
}  // namespace android
