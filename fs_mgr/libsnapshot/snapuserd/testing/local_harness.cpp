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

#include "local_harness.h"

#include <snapuserd/snapuserd_kernel.h>
#include "block_server_local.h"
#include "snapuserd_logging.h"

namespace android {
namespace snapshot {

LocalUserDeviceFd::LocalUserDeviceFd(std::shared_ptr<LocalBlockServerQueue> queue)
    : queue_(queue) {}

bool LocalUserDeviceFd::ReadFullyAtOffset(void* buffer, size_t size, off_t offset) {
    if (size == 0) {
        return true;
    }

    // Align the first sector down.
    uint64_t start_sector = offset / SECTOR_SIZE;

    // Align the last sector up.
    uint64_t end_sector = offset + size;
    end_sector += SECTOR_SIZE - 1;
    end_sector /= SECTOR_SIZE;

    CHECK(start_sector != end_sector);

    // Read all sectors.
    size_t read_size = (end_sector - start_sector) * SECTOR_SIZE;
    std::string temp_buffer(read_size, '\0');
    if (!queue_->Read(start_sector, temp_buffer.data(), temp_buffer.size())) {
        return false;
    }

    // Copy back only the bits the user asked for.
    uint64_t sector_offset = offset - (start_sector * SECTOR_SIZE);
    CHECK(sector_offset + size <= temp_buffer.size());

    memcpy(buffer, temp_buffer.data() + sector_offset, size);
    return true;
}

LocalUserDevice::LocalUserDevice(std::shared_ptr<LocalBlockServerFactory> factory,
                                 std::shared_ptr<LocalBlockServerQueue> queue)
    : factory_(factory), queue_(queue) {}

std::unique_ptr<IUserDeviceFd> LocalUserDevice::OpenFd() {
    return std::make_unique<LocalUserDeviceFd>(queue_);
}

bool LocalUserDevice::Destroy() {
    if (!queue_) {
        return true;
    }
    if (!factory_->DeleteDevice(queue_->misc_name())) {
        return false;
    }
    queue_ = nullptr;
    factory_ = nullptr;
    return true;
}

LocalUserTestHarness::LocalUserTestHarness() {
    block_server_factory_ = std::make_shared<LocalBlockServerFactory>();
}

std::unique_ptr<IUserDevice> LocalUserTestHarness::CreateUserDevice(const std::string&,
                                                                    const std::string& misc_name,
                                                                    uint64_t num_sectors) {
    auto queue = block_server_factory_->AddDevice(misc_name, num_sectors);
    if (!queue) {
        return nullptr;
    }
    return std::make_unique<LocalUserDevice>(block_server_factory_, queue);
}

IBlockServerFactory* LocalUserTestHarness::GetBlockServerFactory() {
    return block_server_factory_.get();
}

}  // namespace snapshot
}  // namespace android
