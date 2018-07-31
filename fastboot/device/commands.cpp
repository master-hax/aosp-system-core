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

#include "commands.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/android_reboot.h>
#include <ext4_utils/wipe.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>
#include <uuid/uuid.h>

#include "fastboot_device.h"
#include "flashing.h"

using ::android::hardware::hidl_string;
using ::android::hardware::boot::V1_0::BoolResult;
using ::android::hardware::boot::V1_0::CommandResult;
using ::android::hardware::boot::V1_0::Slot;
using namespace android::fs_mgr;

void GetVarHandler(FastbootDevice* device, const std::vector<std::string>& args,
                   StatusCb status_cb) {
    auto result = device->GetVariable(GetArg(args), GetSubArgs(args));
    if (result) {
        status_cb(FastbootResult::OKAY, *result);
    } else {
        status_cb(FastbootResult::FAIL, "Unknown variable");
    }
}

void EraseHandler(FastbootDevice* device, const std::vector<std::string>& args,
                  StatusCb status_cb) {
    PartitionHandle handle;
    if (!device->OpenPartition(GetArg(args), &handle)) {
        status_cb(FastbootResult::FAIL, "Partition doesn't exist");
        return;
    }
    if (wipe_block_device(handle.fd(), get_block_device_size(handle.fd())) == 0) {
        status_cb(FastbootResult::OKAY, "Erasing succeeded");
    } else {
        status_cb(FastbootResult::FAIL, "Erasing failed");
    }
}

void DownloadHandler(FastbootDevice* device, const std::vector<std::string>& args,
                     StatusCb status_cb, DataCb data_cb) {
    unsigned int size = strtoul(GetArg(args).c_str(), nullptr, 16);
    if (size == 0 || size > 0xFFFFFFFF) {
        status_cb(FastbootResult::FAIL, "Invalid size");
        return;
    }
    device->GetDownloadData().resize(size);
    status_cb(FastbootResult::DATA, android::base::StringPrintf("%08x", size));

    if (data_cb(device->GetDownloadData(), true)) {
        status_cb(FastbootResult::OKAY, "");
    } else {
        LOG(ERROR) << "Couldn't download data";
        status_cb(FastbootResult::FAIL, "Couldn't download data");
    }
}

void FlashHandler(FastbootDevice* device, const std::vector<std::string>& args,
                  StatusCb status_cb) {
    int ret = device->Flash(GetArg(args));
    if (ret < 0) {
        status_cb(FastbootResult::FAIL, strerror(-ret));
    } else {
        status_cb(FastbootResult::OKAY, "Flashing succeeded");
    }
}

void SetActiveHandler(FastbootDevice* device, const std::vector<std::string>& args,
                      StatusCb status_cb) {
    std::string arg = GetArg(args);
    if (arg.size() != 1) {
        status_cb(FastbootResult::FAIL, "Invalid slot");
        return;
    }

    /*
     * Slot suffix needs to be between 'a' and 'z'.
     */
    if (arg[0] < 'a' || arg[0] > 'z') {
        status_cb(FastbootResult::FAIL, "Bad Slot suffix");
        return;
    }

    Slot slot = arg[0] - 'a';

    auto boot_control_hal = device->boot_control_module();
    /*
     * Non-A/B devices may not have boot control HAL.
     */
    if (!boot_control_hal) {
        status_cb(FastbootResult::FAIL, "Cannot set slot: boot control HAL absent");
        return;
    }

    if (slot >= boot_control_hal->getNumberSlots()) {
        status_cb(FastbootResult::FAIL, "Slot out of range");
        return;
    }
    auto cb = [](CommandResult error) {};
    boot_control_hal->setActiveBootSlot(slot, cb);
    status_cb(FastbootResult::OKAY, "");
}

void ShutDownHandler(FastbootDevice* device, StatusCb status_cb) {
    status_cb(FastbootResult::OKAY, "Shutting down");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "shutdown,");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
}

void RebootHandler(FastbootDevice* device, StatusCb status_cb) {
    status_cb(FastbootResult::OKAY, "Rebooting");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
}

void RebootBootloaderHandler(FastbootDevice* device, StatusCb status_cb) {
    status_cb(FastbootResult::OKAY, "Rebooting bootloader");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,bootloader");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
}

void RebootFastbootHandler(FastbootDevice* device, StatusCb status_cb) {
    status_cb(FastbootResult::OKAY, "Rebooting fastboot");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,fastboot");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
}

static void EnterRecovery() {
    const char msg_switch_to_recovery = 'r';

    android::base::unique_fd sock(socket(AF_UNIX, SOCK_STREAM, 0));
    if (sock < 0) {
        PLOG(ERROR) << "Couldn't create sock";
        return;
    }

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, "/dev/socket/recovery", sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        PLOG(ERROR) << "Couldn't connect to recovery";
        return;
    }

    int ret = write(sock, &msg_switch_to_recovery, sizeof(msg_switch_to_recovery));
    if (ret != sizeof(msg_switch_to_recovery)) {
        PLOG(ERROR) << "Couldn't write message to switch to recovery";
    }
}

void RebootRecoveryHandler(FastbootDevice* device, StatusCb status_cb) {
    status_cb(FastbootResult::OKAY, "Rebooting recovery");
    EnterRecovery();
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
}

// Helper class for opening a handle to a MetadataBuilder and writing the new
// partition table to the same place it was read.
class PartitionBuilder {
  public:
    explicit PartitionBuilder(FastbootDevice* device);
    PartitionBuilder(const PartitionBuilder&) = delete;
    void operator=(const PartitionBuilder&) = delete;

    bool Write();
    bool Valid() const { return !!builder_; }
    MetadataBuilder* operator->() const { return builder_.get(); }

  private:
    std::string super_device_;
    uint32_t slot_number_;
    std::unique_ptr<MetadataBuilder> builder_;
};

PartitionBuilder::PartitionBuilder(FastbootDevice* device) {
    auto super_device = FindPhysicalPartition(LP_METADATA_PARTITION_NAME);
    if (!super_device) {
        return;
    }
    super_device_ = *super_device;

    std::string slot = device->GetCurrentSlot();
    slot_number_ = SlotNumberForSlotSuffix(slot);

    std::unique_ptr<LpMetadata> metadata = ReadMetadata(super_device_.c_str(), slot_number_);
    if (!metadata) {
        return;
    }
    builder_ = MetadataBuilder::New(*metadata.get());
}

bool PartitionBuilder::Write() {
    std::unique_ptr<LpMetadata> metadata = builder_->Export();
    if (!metadata) {
        return false;
    }
    return UpdatePartitionTable(super_device_, *metadata.get(), slot_number_);
}

void CreatePartitionHandler(FastbootDevice* device, const std::vector<std::string>& args,
                            StatusCb status_cb) {
    if (args.size() < 2) {
        status_cb(FastbootResult::FAIL, "Invalid partition name and size");
        return;
    }

    uint64_t partition_size;
    std::string partition_name = args[0];
    if (!android::base::ParseUint(args[1].c_str(), &partition_size)) {
        status_cb(FastbootResult::FAIL, "Invalid partition size");
        return;
    }

    PartitionBuilder builder(device);
    if (!builder.Valid()) {
        status_cb(FastbootResult::FAIL, "Could not open super partition");
        return;
    }
    if (builder->FindPartition(partition_name)) {
        status_cb(FastbootResult::FAIL, "Partition already exists");
        return;
    }

    // Make a random UUID, since they're not currently used.
    uuid_t uuid;
    char uuid_str[37];
    uuid_generate_random(uuid);
    uuid_unparse(uuid, uuid_str);

    Partition* partition = builder->AddPartition(partition_name, uuid_str, 0);
    if (!partition) {
        status_cb(FastbootResult::FAIL, "Failed to add partition");
        return;
    }
    if (!builder->GrowPartition(partition, partition_size)) {
        builder->RemovePartition(partition_name);
        status_cb(FastbootResult::FAIL, "Not enough space for partition");
        return;
    }
    if (!builder.Write()) {
        status_cb(FastbootResult::FAIL, "Failed to write partition table");
        return;
    }
    status_cb(FastbootResult::OKAY, "Partition created");
}

void DeletePartitionHandler(FastbootDevice* device, const std::vector<std::string>& args,
                            StatusCb status_cb) {
    if (args.size() < 1) {
        status_cb(FastbootResult::FAIL, "Invalid partition name and size");
        return;
    }

    PartitionBuilder builder(device);
    if (!builder.Valid()) {
        status_cb(FastbootResult::FAIL, "Could not open super partition");
        return;
    }
    builder->RemovePartition(args[0]);
    if (!builder.Write()) {
        status_cb(FastbootResult::FAIL, "Failed to write partition table");
        return;
    }
    status_cb(FastbootResult::OKAY, "Partition deleted");
}

void ResizePartitionHandler(FastbootDevice* device, const std::vector<std::string>& args,
                            StatusCb status_cb) {
    if (args.size() < 2) {
        status_cb(FastbootResult::FAIL, "Invalid partition name and size");
        return;
    }

    uint64_t partition_size;
    std::string partition_name = args[0];
    if (!android::base::ParseUint(args[1].c_str(), &partition_size)) {
        status_cb(FastbootResult::FAIL, "Invalid partition size");
        return;
    }

    PartitionBuilder builder(device);
    if (!builder.Valid()) {
        status_cb(FastbootResult::FAIL, "Could not open super partition");
        return;
    }

    Partition* partition = builder->FindPartition(partition_name);
    if (!partition) {
        status_cb(FastbootResult::FAIL, "Partition does not exist");
        return;
    }
    if (!builder->ResizePartition(partition, partition_size)) {
        status_cb(FastbootResult::FAIL, "Not enough space to resize partition");
        return;
    }
    if (!builder.Write()) {
        status_cb(FastbootResult::FAIL, "Failed to write partition table");
        return;
    }
    status_cb(FastbootResult::OKAY, "Partition resized");
}
