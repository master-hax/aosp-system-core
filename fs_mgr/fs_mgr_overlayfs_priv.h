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

#pragma once

#include <stdint.h>

#include <string>

static constexpr char kUpperName[] = "upper";
static constexpr char kWorkName[] = "work";
static constexpr char kOverlayTopDir[] = "/overlay";
static constexpr char kScratchMountPoint[] = "/mnt/scratch";
static constexpr char kOverlayfsFileContext[] = "u:object_r:overlayfs_file:s0";
static constexpr char kMkF2fs[] = "/system/bin/make_f2fs";
static constexpr char kMkExt4[] = "/system/bin/mke2fs";

uint32_t fs_mgr_overlayfs_slot_number();
std::string fs_mgr_overlayfs_super_device(uint32_t slot_number);
bool fs_mgr_access(const std::string& path);
bool fs_mgr_rw_access(const std::string& path);
bool fs_mgr_overlayfs_already_mounted(const std::string& mount_point, bool overlay_only = true);
void fs_mgr_overlayfs_umount_scratch();
const std::string fs_mgr_mount_point(const std::string& mount_point);
std::vector<std::string> GetOverlayMountPoints();
std::string fs_mgr_overlayfs_scratch_mount_type();
bool fs_mgr_overlayfs_mount_scratch(const std::string& device_path, const std::string mnt_type,
                                    bool readonly = false);
bool fs_mgr_filesystem_has_space(const std::string& mount_point);

enum class ScratchStrategy {
    kNone,
    // DAP device, use logical partitions.
    kDynamicPartition,
    // Retrofit DAP device, use super_<other>.
    kSuperOther,
    // Pre-DAP device, uses the other slot.
    kSystemOther
};

// Return the strategy this device must use for creating a scratch partition.
ScratchStrategy GetScratchStrategy(std::string* backing_device = nullptr);

// Return the scratch device if it exists.
std::string GetScratchDevice();
