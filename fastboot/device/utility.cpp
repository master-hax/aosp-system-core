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

#include "utility.h"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>

#include "fastboot_device.h"

using namespace android::fs_mgr;
using namespace std::chrono_literals;
using android::base::unique_fd;
using android::hardware::boot::V1_0::Slot;

static bool OpenPhysicalPartition(const std::string& name, PartitionHandle* handle) {
    std::optional<std::string> path = FindPhysicalPartition(name);
    if (!path) {
        return false;
    }
    *handle = PartitionHandle(*path);
    return true;
}

static bool OpenLogicalPartition(const std::string& name, const std::string& slot,
                                 PartitionHandle* handle) {
    std::optional<std::string> path = FindPhysicalPartition(fs_mgr_get_super_partition_name());
    if (!path) {
        return false;
    }
    uint32_t slot_number = SlotNumberForSlotSuffix(slot);
    std::string dm_path;
    if (!CreateLogicalPartition(path->c_str(), slot_number, name, true, 5s, &dm_path)) {
        LOG(ERROR) << "Could not map partition: " << name;
        return false;
    }
    auto closer = [name]() -> void { DestroyLogicalPartition(name, 5s); };
    *handle = PartitionHandle(dm_path, std::move(closer));
    return true;
}

bool OpenPartition(FastbootDevice* device, const std::string& name, PartitionHandle* handle) {
    // We prioritize logical partitions over physical ones, and do this
    // consistently for other partition operations (like getvar:partition-size).
    if (LogicalPartitionExists(name, device->GetCurrentSlot())) {
        if (!OpenLogicalPartition(name, device->GetCurrentSlot(), handle)) {
            return false;
        }
    } else if (!OpenPhysicalPartition(name, handle)) {
        LOG(ERROR) << "No such partition: " << name;
        return false;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(handle->path().c_str(), O_WRONLY | O_EXCL)));
    if (fd < 0) {
        PLOG(ERROR) << "Failed to open block device: " << handle->path();
        return false;
    }
    handle->set_fd(std::move(fd));
    return true;
}

std::optional<std::string> FindPhysicalPartition(const std::string& name) {
    // Check for an invalid file name
    if (android::base::StartsWith(name, "../") || name.find("/../") != std::string::npos) {
        return {};
    }
    std::string path = "/dev/block/by-name/" + name;
    if (access(path.c_str(), W_OK) < 0) {
        return {};
    }
    return path;
}

static const LpMetadataPartition* FindLogicalPartition(const LpMetadata& metadata,
                                                       const std::string& name) {
    for (const auto& partition : metadata.partitions) {
        if (GetPartitionName(partition) == name) {
            return &partition;
        }
    }
    return nullptr;
}

bool LogicalPartitionExists(const std::string& name, const std::string& slot_suffix,
                            bool* is_zero_length) {
    auto path = FindPhysicalPartition(fs_mgr_get_super_partition_name());
    if (!path) {
        return false;
    }

    uint32_t slot_number = SlotNumberForSlotSuffix(slot_suffix);
    std::unique_ptr<LpMetadata> metadata = ReadMetadata(path->c_str(), slot_number);
    if (!metadata) {
        return false;
    }
    const LpMetadataPartition* partition = FindLogicalPartition(*metadata.get(), name);
    if (!partition) {
        return false;
    }
    if (is_zero_length) {
        *is_zero_length = (partition->num_extents == 0);
    }
    return true;
}

bool GetSlotNumber(const std::string& slot, Slot* number) {
    if (slot.size() != 1) {
        return false;
    }
    if (slot[0] < 'a' || slot[0] > 'z') {
        return false;
    }
    *number = slot[0] - 'a';
    return true;
}

std::vector<std::string> ListPartitions(FastbootDevice* device) {
    std::vector<std::string> partitions;

    // First get physical partitions.
    struct dirent* de;
    std::unique_ptr<DIR, decltype(&closedir)> by_name(opendir("/dev/block/by-name"), closedir);
    while ((de = readdir(by_name.get())) != nullptr) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
            continue;
        }
        struct stat s;
        std::string path = "/dev/block/by-name/" + std::string(de->d_name);
        if (!stat(path.c_str(), &s) && S_ISBLK(s.st_mode)) {
            partitions.emplace_back(de->d_name);
        }
    }

    // Next get logical partitions.
    if (auto path = FindPhysicalPartition(fs_mgr_get_super_partition_name())) {
        uint32_t slot_number = SlotNumberForSlotSuffix(device->GetCurrentSlot());
        if (auto metadata = ReadMetadata(path->c_str(), slot_number)) {
            for (const auto& partition : metadata->partitions) {
                std::string partition_name = GetPartitionName(partition);
                partitions.emplace_back(partition_name);
            }
        }
    }
    return partitions;
}

bool GetDeviceLockStatus() {
    std::string cmdline;
    // Return lock status true if unable to read kernel command line.
    if (!android::base::ReadFileToString("/proc/cmdline", &cmdline)) {
        return true;
    }
    return cmdline.find("androidboot.verifiedbootstate=orange") == std::string::npos;
}

namespace {

bool UpdateAllMetadataSlots(const std::string& super_partition,
                            const android::fs_mgr::LpMetadata& metadata) {
    bool ok = true;
    for (size_t i = 0; i < metadata.geometry.metadata_slot_count; i++) {
        ok &= UpdatePartitionTable(super_partition, metadata, i);
    }
    return ok;
}

}  // namespace

void UpgradeRetrofitSuperIfNeeded() {
    if (!android::base::GetBoolProperty("ro.boot.logical_partitions_retrofit", false)) {
        return;
    }
    if (GetDeviceLockStatus()) {
        // For safety, don't write anything if the device is locked.
        return;
    }

    // Determine the current and other slot suffixes/numbers.
    std::string current_slot_suffix = fs_mgr_get_slot_suffix();
    if (current_slot_suffix.empty()) {
        return;
    }
    uint32_t current_slot = SlotNumberForSlotSuffix(current_slot_suffix);
    std::string other_slot_suffix = (current_slot_suffix == "_a") ? "_b" : "_a";
    uint32_t other_slot = SlotNumberForSlotSuffix(other_slot_suffix);

    // Read the existing metadata. If there isn't any, the super partition
    // is corrupt. We don't do anything since the device needs to be
    // reflashed.
    std::string current_super = fs_mgr_get_super_partition_name(current_slot);
    auto current_metadata = ReadMetadata(current_super, current_slot);
    if (!current_metadata) {
        return;
    }

    // Get an upgraded copy.
    PartitionOpener opener;
    auto builder = MetadataBuilder::NewForUpdate(opener, current_super, current_slot, other_slot);
    if (!builder) {
        LOG(ERROR) << "Unable to import metadata for retrofit device.";
        return;
    }
    auto upgraded_metadata = builder->Export();
    if (!upgraded_metadata) {
        LOG(ERROR) << "Unable to export metadata for retrofit device.";
        return;
    }

    // If the upgraded metadata has the same block device list as the current
    // metadata, we don't need t do anything.
    if (upgraded_metadata->block_devices.size() == current_metadata->block_devices.size()) {
        return;
    }

    // Otherwise, it's time to upgrade the device. This is a destructive
    // operation since (1) we will be flashing over the existing other slot,
    // and (2) flash operations could start writing over the existing slot
    // as well, even unintentionally (for example if the current slot does
    // not have enough space to store a partition).
    //
    // Thus, we log that we're about to do this.
    LOG(WARNING) << "This device has been upgraded to dynamic partitions, and will now be updated"
                 << " to use both slots for allocating partition data.";
    LOG(WARNING) << "This will overwrite the contents of slot " << other_slot_suffix << ".";

    std::string other_super = fs_mgr_get_super_partition_name(other_slot);
    if (!UpdateAllMetadataSlots(current_super, *upgraded_metadata.get())) {
        LOG(ERROR) << "Updating metadata on " << current_super << " failed.";
    }
    if (!FlashPartitionTable(other_super, *upgraded_metadata.get())) {
        LOG(ERROR) << "Updating metadata on " << other_super << " failed.";
    }
}

bool UpdateAllPartitionMetadata(const std::string& super_name,
                                const android::fs_mgr::LpMetadata& metadata) {
    if (!UpdateAllMetadataSlots(super_name, metadata)) {
        return false;
    }
    if (!android::base::GetBoolProperty("ro.boot.logical_partitions_retrofit", false)) {
        // No more locations to update the metadata.
        return true;
    }
    std::string slot_suffix = GetPartitionSlotSuffix(super_name);
    if (slot_suffix.empty()) {
        return true;
    }

    // If this update operation fails, it probably means UpgradeRetrofitSuperIfNeeded
    // was never called, so the other partition doesn't have its geometry laid down.
    std::string other_slot_suffix = (slot_suffix == "_a") ? "_b" : "_a";
    std::string other_super =
            super_name.substr(0, super_name.size() - slot_suffix.size()) + other_slot_suffix;
    return UpdateAllMetadataSlots(other_super, metadata);
}
