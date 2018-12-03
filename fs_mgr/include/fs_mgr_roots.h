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

#pragma once

#include <string>

#include <fs_mgr.h>

// Finds the volume specified by the given path. fs_mgr_get_entry_for_mount_point() does exact match
// only, so it attempts the prefixes recursively (e.g. "/cache/recovery/last_log",
// "/cache/recovery", "/cache", "/" for a given path of "/cache/recovery/last_log") and returns the
// first match or nullptr.
struct fstab_rec* fs_mgr_fstab_rec_for_path(struct fstab* fstab, const char* path);

// Make sure that the volume 'path' is on is mounted at 'mount_point'. If 'mount_point' is nullptr,
// use mount_point specified in default fstab. Returns 0 on success (volume is mounted).
int fs_mgr_ensure_path_mounted_at(const char* path, const char* mount_point);

// Similar fs_mgr_ensure_path_mounted_at, but allows one to specify the fstab to use.
int fs_mgr_fstab_ensure_path_mounted_at(struct fstab* fstab, const char* path,
                                        const char* mount_point);

// Return "/system" if it is in default fstab, otherwise "/".
std::string fs_mgr_get_system_root();

// Return true iff logical partitions are mapped when partitions are mounted via ensure_path_mounted
// functions.
bool fs_mgr_logical_partitions_mapped();
