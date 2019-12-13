// Copyright (C) 2019 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <sys/types.h>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr/remount.h>
#include <fs_mgr_dm_linear.h>
#include <fs_mgr_overlayfs.h>
#include <libdm/dm.h>
#include <liblp/builder.h>

#include "fs_mgr_overlayfs_priv.h"
#include "fs_mgr_priv.h"

namespace android {
namespace fs_mgr {

using namespace std::string_literals;
using android::dm::DeviceMapper;
using android::dm::DmDeviceState;
using android::fs_mgr::DestroyLogicalPartition;
using android::fs_mgr::MetadataBuilder;

// Return true if everything is mounted, but before adb is started.  Right
// after 'trigger load_persist_props_action' is done.
bool fs_mgr_boot_completed() {
    return android::base::GetBoolProperty("ro.persistent_properties.ready", false);
}

bool fs_mgr_overlayfs_has_logical(const Fstab& fstab) {
    for (const auto& entry : fstab) {
        if (entry.fs_mgr_flags.logical) {
            return true;
        }
    }
    return false;
}

bool fs_mgr_overlayfs_setup_dir(const std::string& dir, std::string* overlay, bool* change) {
    auto ret = true;
    auto top = dir + kOverlayTopDir;
    if (setfscreatecon(kOverlayfsFileContext)) {
        ret = false;
        PERROR << "setfscreatecon " << kOverlayfsFileContext;
    }
    auto save_errno = errno;
    if (!mkdir(top.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "mkdir " << top;
    } else {
        errno = save_errno;
    }
    setfscreatecon(nullptr);

    if (overlay) *overlay = std::move(top);
    return ret;
}

bool fs_mgr_overlayfs_setup_one(const std::string& overlay, const std::string& mount_point,
                                bool* change) {
    auto ret = true;
    if (fs_mgr_overlayfs_already_mounted(mount_point)) return ret;
    auto fsrec_mount_point = overlay + "/" + android::base::Basename(mount_point) + "/";

    if (setfscreatecon(kOverlayfsFileContext)) {
        ret = false;
        PERROR << "setfscreatecon " << kOverlayfsFileContext;
    }
    auto save_errno = errno;
    if (!mkdir(fsrec_mount_point.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "mkdir " << fsrec_mount_point;
    } else {
        errno = save_errno;
    }

    save_errno = errno;
    if (!mkdir((fsrec_mount_point + kWorkName).c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "mkdir " << fsrec_mount_point << kWorkName;
    } else {
        errno = save_errno;
    }
    setfscreatecon(nullptr);

    auto new_context = fs_mgr_get_context(mount_point);
    if (!new_context.empty() && setfscreatecon(new_context.c_str())) {
        ret = false;
        PERROR << "setfscreatecon " << new_context;
    }
    auto upper = fsrec_mount_point + kUpperName;
    save_errno = errno;
    if (!mkdir(upper.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "mkdir " << upper;
    } else {
        errno = save_errno;
    }
    if (!new_context.empty()) setfscreatecon(nullptr);

    return ret;
}

static void TruncatePartitionsWithSuffix(MetadataBuilder* builder, const std::string& suffix) {
    auto& dm = DeviceMapper::Instance();

    // Remove <other> partitions
    for (const auto& group : builder->ListGroups()) {
        for (const auto& part : builder->ListPartitionsInGroup(group)) {
            const auto& name = part->name();
            if (!android::base::EndsWith(name, suffix)) {
                continue;
            }
            if (dm.GetState(name) != DmDeviceState::INVALID && !DestroyLogicalPartition(name)) {
                continue;
            }
            builder->ResizePartition(builder->FindPartition(name), 0);
        }
    }
}

// Create or update a scratch partition within super.
static bool CreateDynamicScratch(const Fstab& fstab, std::string* scratch_device,
                                 bool* partition_exists, bool* change) {
    const auto partition_name = android::base::Basename(kScratchMountPoint);

    auto& dm = DeviceMapper::Instance();
    *partition_exists = dm.GetState(partition_name) != DmDeviceState::INVALID;

    auto partition_create = !*partition_exists;
    auto slot_number = fs_mgr_overlayfs_slot_number();
    auto super_device = fs_mgr_overlayfs_super_device(slot_number);
    if (!fs_mgr_rw_access(super_device)) return false;
    if (!fs_mgr_overlayfs_has_logical(fstab)) return false;
    auto builder = MetadataBuilder::New(super_device, slot_number);
    if (!builder) {
        LERROR << "open " << super_device << " metadata";
        return false;
    }
    auto partition = builder->FindPartition(partition_name);
    *partition_exists = partition != nullptr;
    auto changed = false;
    if (!*partition_exists) {
        partition = builder->AddPartition(partition_name, LP_PARTITION_ATTR_NONE);
        if (!partition) {
            LERROR << "create " << partition_name;
            return false;
        }
        changed = true;
    }
    // Take half of free space, minimum 512MB or maximum free - margin.
    static constexpr auto kMinimumSize = uint64_t(512 * 1024 * 1024);
    if (partition->size() < kMinimumSize) {
        auto partition_size =
                builder->AllocatableSpace() - builder->UsedSpace() + partition->size();
        if ((partition_size > kMinimumSize) || !partition->size()) {
            // Leave some space for free space jitter of a few erase
            // blocks, in case they are needed for any individual updates
            // to any other partition that needs to be flashed while
            // overlayfs is in force.  Of course if margin_size is not
            // enough could normally get a flash failure, so
            // ResizePartition() will delete the scratch partition in
            // order to fulfill.  Deleting scratch will destroy all of
            // the adb remount overrides :-( .
            auto margin_size = uint64_t(3 * 256 * 1024);
            BlockDeviceInfo info;
            if (builder->GetBlockDeviceInfo(fs_mgr_get_super_partition_name(slot_number), &info)) {
                margin_size = 3 * info.logical_block_size;
            }
            partition_size = std::max(std::min(kMinimumSize, partition_size - margin_size),
                                      partition_size / 2);
            if (partition_size > partition->size()) {
                if (!builder->ResizePartition(partition, partition_size)) {
                    // Try to free up space by deallocating partitions in the other slot.
                    TruncatePartitionsWithSuffix(builder.get(), fs_mgr_get_other_slot_suffix());

                    partition_size =
                            builder->AllocatableSpace() - builder->UsedSpace() + partition->size();
                    partition_size = std::max(std::min(kMinimumSize, partition_size - margin_size),
                                              partition_size / 2);
                    if (!builder->ResizePartition(partition, partition_size)) {
                        LERROR << "resize " << partition_name;
                        return false;
                    }
                }
                if (!partition_create) DestroyLogicalPartition(partition_name);
                changed = true;
                *partition_exists = false;
            }
        }
    }
    // land the update back on to the partition
    if (changed) {
        auto metadata = builder->Export();
        if (!metadata || !UpdatePartitionTable(super_device, *metadata.get(), slot_number)) {
            LERROR << "add partition " << partition_name;
            return false;
        }

        if (change) *change = true;
    }

    if (changed || partition_create) {
        CreateLogicalPartitionParams params = {
                .block_device = super_device,
                .metadata_slot = slot_number,
                .partition_name = partition_name,
                .force_writable = true,
                .timeout_ms = 10s,
        };
        if (!CreateLogicalPartition(params, scratch_device)) {
            return false;
        }

        if (change) *change = true;
    }
    return true;
}

bool fs_mgr_overlayfs_create_scratch(const Fstab& fstab, std::string* scratch_device,
                                     bool* partition_exists, bool* change) {
    auto strategy = GetScratchStrategy();
    if (strategy == ScratchStrategy::kDynamicPartition) {
        return CreateDynamicScratch(fstab, scratch_device, partition_exists, change);
    }

    // The scratch partition can only be landed on a physical partition if we
    // get here. If there are no viable candidates that are R/W, just return
    // that there is no device.
    *scratch_device = GetScratchDevice();
    if (scratch_device->empty()) {
        errno = ENXIO;
        return false;
    }
    *partition_exists = true;
    return true;
}

bool fs_mgr_overlayfs_make_scratch(const std::string& scratch_device, const std::string& mnt_type) {
    // Force mkfs by design for overlay support of adb remount, simplify and
    // thus do not rely on fsck to correct problems that could creep in.
    auto command = ""s;
    if (mnt_type == "f2fs") {
        command = std::string(kMkF2fs) + " -w 4096 -f -d1 -l" +
                  android::base::Basename(kScratchMountPoint);
    } else if (mnt_type == "ext4") {
        command = std::string(kMkExt4) + " -F -b 4096 -t ext4 -m 0 -O has_journal -M " +
                  kScratchMountPoint;
    } else {
        errno = ESRCH;
        LERROR << mnt_type << " has no mkfs cookbook";
        return false;
    }
    command += " " + scratch_device + " >/dev/null 2>/dev/null </dev/null";
    fs_mgr_set_blk_ro(scratch_device, false);
    auto ret = system(command.c_str());
    if (ret) {
        LERROR << "make " << mnt_type << " filesystem on " << scratch_device << " return=" << ret;
        return false;
    }
    return true;
}

// Create and mount kScratchMountPoint storage if we have logical partitions
bool fs_mgr_overlayfs_setup_scratch(const Fstab& fstab, bool* change) {
    if (fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) return true;

    std::string scratch_device;
    bool partition_exists;
    if (!fs_mgr_overlayfs_create_scratch(fstab, &scratch_device, &partition_exists, change)) {
        return false;
    }

    // If the partition exists, assume first that it can be mounted.
    auto mnt_type = fs_mgr_overlayfs_scratch_mount_type();
    if (partition_exists) {
        if (fs_mgr_overlayfs_mount_scratch(scratch_device, mnt_type)) {
            auto path = std::string(kScratchMountPoint) + kOverlayTopDir;
            if (!fs_mgr_access(path) && !fs_mgr_filesystem_has_space(kScratchMountPoint)) {
                // declare it useless, no overrides and no free space
                fs_mgr_overlayfs_umount_scratch();
            } else {
                if (change) *change = true;
                return true;
            }
        }
        // partition existed, but was not initialized; fall through to make it.
        errno = 0;
    }

    if (!fs_mgr_overlayfs_make_scratch(scratch_device, mnt_type)) return false;

    if (change) *change = true;

    return fs_mgr_overlayfs_mount_scratch(scratch_device, mnt_type);
}

bool fs_mgr_overlayfs_teardown_scratch(const std::string& overlay, bool* change) {
    // umount and delete kScratchMountPoint storage if we have logical partitions
    if (overlay != kScratchMountPoint) return true;
    auto slot_number = fs_mgr_overlayfs_slot_number();
    auto super_device = fs_mgr_overlayfs_super_device(slot_number);
    if (!fs_mgr_rw_access(super_device)) return true;

    auto save_errno = errno;
    if (fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) {
        fs_mgr_overlayfs_umount_scratch();
    }
    auto builder = MetadataBuilder::New(super_device, slot_number);
    if (!builder) {
        errno = save_errno;
        return true;
    }
    const auto partition_name = android::base::Basename(kScratchMountPoint);
    if (builder->FindPartition(partition_name) == nullptr) {
        errno = save_errno;
        return true;
    }
    builder->RemovePartition(partition_name);
    auto metadata = builder->Export();
    if (metadata && UpdatePartitionTable(super_device, *metadata.get(), slot_number)) {
        if (change) *change = true;
        if (!DestroyLogicalPartition(partition_name)) return false;
    } else {
        LERROR << "delete partition " << overlay;
        return false;
    }
    errno = save_errno;
    return true;
}

bool fs_mgr_rm_all(const std::string& path, bool* change = nullptr, int level = 0) {
    auto save_errno = errno;
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()), closedir);
    if (!dir) {
        if (errno == ENOENT) {
            errno = save_errno;
            return true;
        }
        PERROR << "opendir " << path << " depth=" << level;
        if ((errno == EPERM) && (level != 0)) {
            errno = save_errno;
            return true;
        }
        return false;
    }
    dirent* entry;
    auto ret = true;
    while ((entry = readdir(dir.get()))) {
        if (("."s == entry->d_name) || (".."s == entry->d_name)) continue;
        auto file = path + "/" + entry->d_name;
        if (entry->d_type == DT_UNKNOWN) {
            struct stat st;
            save_errno = errno;
            if (!lstat(file.c_str(), &st) && (st.st_mode & S_IFDIR)) entry->d_type = DT_DIR;
            errno = save_errno;
        }
        if (entry->d_type == DT_DIR) {
            ret &= fs_mgr_rm_all(file, change, level + 1);
            if (!rmdir(file.c_str())) {
                if (change) *change = true;
            } else {
                if (errno != ENOENT) ret = false;
                PERROR << "rmdir " << file << " depth=" << level;
            }
            continue;
        }
        if (!unlink(file.c_str())) {
            if (change) *change = true;
        } else {
            if (errno != ENOENT) ret = false;
            PERROR << "rm " << file << " depth=" << level;
        }
    }
    return ret;
}

bool fs_mgr_overlayfs_teardown_one(const std::string& overlay, const std::string& mount_point,
                                   bool* change) {
    const auto top = overlay + kOverlayTopDir;

    if (!fs_mgr_access(top)) return fs_mgr_overlayfs_teardown_scratch(overlay, change);

    auto cleanup_all = mount_point.empty();
    const auto partition_name = android::base::Basename(mount_point);
    const auto oldpath = top + (cleanup_all ? "" : ("/" + partition_name));
    const auto newpath = cleanup_all ? overlay + "/." + &kOverlayTopDir[1] + ".teardown"
                                     : top + "/." + partition_name + ".teardown";
    auto ret = fs_mgr_rm_all(newpath);
    auto save_errno = errno;
    if (!rename(oldpath.c_str(), newpath.c_str())) {
        if (change) *change = true;
    } else if (errno != ENOENT) {
        ret = false;
        PERROR << "mv " << oldpath << " " << newpath;
    } else {
        errno = save_errno;
    }
    ret &= fs_mgr_rm_all(newpath, change);
    save_errno = errno;
    if (!rmdir(newpath.c_str())) {
        if (change) *change = true;
    } else if (errno != ENOENT) {
        ret = false;
        PERROR << "rmdir " << newpath;
    } else {
        errno = save_errno;
    }
    if (!cleanup_all) {
        save_errno = errno;
        if (!rmdir(top.c_str())) {
            if (change) *change = true;
            cleanup_all = true;
        } else if (errno == ENOTEMPTY) {
            cleanup_all = true;
            // cleanup all if the content is all hidden (leading .)
            std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(top.c_str()), closedir);
            if (!dir) {
                PERROR << "opendir " << top;
            } else {
                dirent* entry;
                while ((entry = readdir(dir.get()))) {
                    if (entry->d_name[0] != '.') {
                        cleanup_all = false;
                        break;
                    }
                }
            }
            errno = save_errno;
        } else if (errno == ENOENT) {
            cleanup_all = true;
            errno = save_errno;
        } else {
            ret = false;
            PERROR << "rmdir " << top;
        }
    }
    if (cleanup_all) ret &= fs_mgr_overlayfs_teardown_scratch(overlay, change);
    return ret;
}

bool SetupOverlayfs(const char* mount_point, bool* change, bool force) {
    if (change) *change = false;
    auto ret = false;
    if (fs_mgr_overlayfs_valid() == OverlayfsValidResult::kNotSupported) return ret;
    if (!fs_mgr_boot_completed()) {
        errno = EBUSY;
        PERROR << "setup";
        return ret;
    }

    auto save_errno = errno;
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        return false;
    }
    errno = save_errno;
    auto candidates = fs_mgr_overlayfs_candidate_list(fstab);
    for (auto it = candidates.begin(); it != candidates.end();) {
        if (mount_point &&
            (fs_mgr_mount_point(it->mount_point) != fs_mgr_mount_point(mount_point))) {
            it = candidates.erase(it);
            continue;
        }
        save_errno = errno;
        auto verity_enabled = !force && fs_mgr_is_verity_enabled(*it);
        if (errno == ENOENT || errno == ENXIO) errno = save_errno;
        if (verity_enabled) {
            it = candidates.erase(it);
            continue;
        }
        ++it;
    }

    if (candidates.empty()) return ret;

    std::string dir;
    for (const auto& overlay_mount_point : GetOverlayMountPoints()) {
        if (overlay_mount_point == kScratchMountPoint) {
            if (!fs_mgr_overlayfs_setup_scratch(fstab, change)) continue;
        } else {
            if (GetEntryForMountPoint(&fstab, overlay_mount_point) == nullptr) {
                continue;
            }
        }
        dir = overlay_mount_point;
        break;
    }
    if (dir.empty()) {
        if (change && *change) errno = ESRCH;
        if (errno == EPERM) errno = save_errno;
        return ret;
    }

    std::string overlay;
    ret |= fs_mgr_overlayfs_setup_dir(dir, &overlay, change);
    for (const auto& entry : candidates) {
        ret |= fs_mgr_overlayfs_setup_one(overlay, fs_mgr_mount_point(entry.mount_point), change);
    }
    return ret;
}

static bool GetAndMapScratchDeviceIfNeeded(std::string* device) {
    *device = GetScratchDevice();
    if (!device->empty()) {
        return true;
    }

    auto strategy = GetScratchStrategy();
    if (strategy == ScratchStrategy::kDynamicPartition) {
        auto metadata_slot = fs_mgr_overlayfs_slot_number();
        CreateLogicalPartitionParams params = {
                .block_device = fs_mgr_overlayfs_super_device(metadata_slot),
                .metadata_slot = metadata_slot,
                .partition_name = android::base::Basename(kScratchMountPoint),
                .force_writable = true,
                .timeout_ms = 10s,
        };
        return CreateLogicalPartition(params, device);
    }
    return false;
}

// Returns false if teardown not permitted, errno set to last error.
// If something is altered, set *change.
bool TeardownOverlayfs(const char* mount_point, bool* change) {
    if (change) *change = false;
    auto ret = true;
    // If scratch exists, but is not mounted, lets gain access to clean
    // specific override entries.
    auto mount_scratch = false;
    if ((mount_point != nullptr) && !fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) {
        std::string scratch_device;
        if (GetAndMapScratchDeviceIfNeeded(&scratch_device)) {
            mount_scratch = fs_mgr_overlayfs_mount_scratch(scratch_device,
                                                           fs_mgr_overlayfs_scratch_mount_type());
        }
    }
    for (const auto& overlay_mount_point : GetOverlayMountPoints()) {
        ret &= fs_mgr_overlayfs_teardown_one(
                overlay_mount_point, mount_point ? fs_mgr_mount_point(mount_point) : "", change);
    }
    if (fs_mgr_overlayfs_valid() == OverlayfsValidResult::kNotSupported) {
        // After obligatory teardown to make sure everything is clean, but if
        // we didn't want overlayfs in the the first place, we do not want to
        // waste time on a reboot (or reboot request message).
        if (change) *change = false;
    }
    // And now that we did what we could, lets inform
    // caller that there may still be more to do.
    if (!fs_mgr_boot_completed()) {
        errno = EBUSY;
        PERROR << "teardown";
        ret = false;
    }
    if (mount_scratch) fs_mgr_overlayfs_umount_scratch();

    return ret;
}

}  // namespace fs_mgr
}  // namespace android
