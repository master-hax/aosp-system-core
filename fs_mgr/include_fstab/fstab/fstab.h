/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <stdint.h>
#include <sys/types.h>

#include <set>
#include <string>
#include <vector>

std::string fs_mgr_get_slot_suffix();
std::string fs_mgr_get_other_slot_suffix();

namespace android {
namespace fs_mgr {

struct FstabEntry {
    std::string blk_device;
    std::string logical_partition_name;
    std::string mount_point;
    std::string fs_type;
    unsigned long flags = 0;
    std::string fs_options;
    std::string key_loc;
    std::string key_dir;
    off64_t length = 0;
    std::string label;
    int partnum = -1;
    int swap_prio = -1;
    int max_comp_streams = 0;
    off64_t zram_size = 0;
    off64_t reserved_size = 0;
    std::string file_contents_mode;
    std::string file_names_mode;
    off64_t erase_blk_size = 0;
    off64_t logical_blk_size = 0;
    std::string sysfs_path;
    std::string vbmeta_partition;
    std::string zram_loopback_path;
    uint64_t zram_loopback_size = 512 * 1024 * 1024;  // 512MB by default;
    std::string zram_backing_dev_path;
    std::string avb_keys;

    struct FsMgrFlags {
        bool wait : 1;
        bool check : 1;
        bool crypt : 1;
        bool nonremovable : 1;
        bool vold_managed : 1;
        bool recovery_only : 1;
        bool verify : 1;
        bool force_crypt : 1;
        bool no_emulated_sd : 1;  // No emulated sdcard daemon; sd card is the only external
                                  // storage.
        bool no_trim : 1;
        bool file_encryption : 1;
        bool formattable : 1;
        bool slot_select : 1;
        bool force_fde_or_fbe : 1;
        bool late_mount : 1;
        bool no_fail : 1;
        bool verify_at_boot : 1;
        bool quota : 1;
        bool avb : 1;
        bool logical : 1;
        bool checkpoint_blk : 1;
        bool checkpoint_fs : 1;
        bool first_stage_mount : 1;
        bool slot_select_other : 1;
        bool fs_verity : 1;

        bool operator==(const FsMgrFlags& rval) const {
            return (wait == rval.wait) && (check == rval.check) && (crypt == rval.crypt) &&
                   (nonremovable == rval.nonremovable) && (vold_managed == rval.vold_managed) &&
                   (recovery_only == rval.recovery_only) && (verify == rval.verify) &&
                   (force_crypt == rval.force_crypt) && (no_emulated_sd == rval.no_emulated_sd) &&
                   (no_trim == rval.no_trim) && (file_encryption == rval.file_encryption) &&
                   (formattable == rval.formattable) && (slot_select == rval.slot_select) &&
                   (force_fde_or_fbe == rval.force_fde_or_fbe) && (late_mount == rval.late_mount) &&
                   (no_fail == rval.no_fail) && (verify_at_boot == rval.verify_at_boot) &&
                   (quota == rval.quota) && (avb == rval.avb) && (logical == rval.logical) &&
                   (checkpoint_blk == rval.checkpoint_blk) &&
                   (checkpoint_fs == rval.checkpoint_fs) &&
                   (first_stage_mount == rval.first_stage_mount) &&
                   (slot_select_other == rval.slot_select_other) && (fs_verity == rval.fs_verity);
        }
    } fs_mgr_flags = {};

    bool is_encryptable() const {
        return fs_mgr_flags.crypt || fs_mgr_flags.force_crypt || fs_mgr_flags.force_fde_or_fbe;
    }

    bool operator==(const FstabEntry& rval) const {
        return (blk_device == rval.blk_device) &&
               (logical_partition_name == rval.logical_partition_name) &&
               (mount_point == rval.mount_point) && (fs_type == rval.fs_type) &&
               (flags == rval.flags) && (fs_options == rval.fs_options) &&
               (key_loc == rval.key_loc) && (key_dir == rval.key_dir) && (length == rval.length) &&
               (label == rval.label) && (partnum == rval.partnum) &&
               (swap_prio == rval.swap_prio) && (max_comp_streams == rval.max_comp_streams) &&
               (zram_size == rval.zram_size) && (reserved_size == rval.reserved_size) &&
               (file_contents_mode == rval.file_contents_mode) &&
               (file_names_mode == rval.file_names_mode) &&
               (erase_blk_size == rval.erase_blk_size) &&
               (logical_blk_size == rval.logical_blk_size) && (sysfs_path == rval.sysfs_path) &&
               (vbmeta_partition == rval.vbmeta_partition) &&
               (zram_loopback_path == rval.zram_loopback_path) &&
               (zram_loopback_size == rval.zram_loopback_size) &&
               (zram_backing_dev_path == rval.zram_backing_dev_path) &&
               (avb_keys == rval.avb_keys) && (fs_mgr_flags == rval.fs_mgr_flags);
    }
};

// An Fstab is a collection of FstabEntry structs.
// The entries must be kept in the same order as they were seen in the fstab.
// Unless explicitly requested, a lookup on mount point should always return the 1st one.
using Fstab = std::vector<FstabEntry>;

bool ReadFstabFromFile(const std::string& path, Fstab* fstab);
bool ReadFstabFromDt(Fstab* fstab, bool log = true);
bool ReadDefaultFstab(Fstab* fstab);
bool SkipMountingPartitions(Fstab* fstab);

FstabEntry* GetEntryForMountPoint(Fstab* fstab, const std::string& path);

// Helper method to build a GSI fstab entry for mounting /system.
FstabEntry BuildGsiSystemFstabEntry();

std::set<std::string> GetBootDevices();

// Return the name of the dm-verity device for the given fstab entry. This does
// not check whether the device is valid or exists; it merely returns the
// expected name.
std::string GetVerityDeviceName(const FstabEntry& entry);

}  // namespace fs_mgr
}  // namespace android
