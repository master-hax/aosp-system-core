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
#ifndef __CORE_FS_MGR_OVERLAYFS_H
#define __CORE_FS_MGR_OVERLAYFS_H

#include <fstab/fstab.h>

void fs_mgr_overlayfs_mount_all(const fstab* fstab = nullptr);
bool fs_mgr_overlayfs_setup(const fstab* fstab = nullptr, const char* mount_point = nullptr,
                            bool* change = nullptr);
bool fs_mgr_overlayfs_teardown(const fstab* fstab = nullptr, const char* mount_point = nullptr,
                               bool* change = nullptr);

#endif /* __CORE_FS_MGR_OVERLAYFS_H */
