/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <libvbmeta/super_vbmeta_format.h>

namespace android {
namespace fs_mgr {

bool ParseSuperVBMeta(const void* buffer, SuperVBMeta* vbmeta);
bool ReadSuperVBMeta(int fd, uint64_t offset, SuperVBMeta* vbmeta);

bool ReadSuperPrimaryVBMeta(int fd, SuperVBMeta* vbmeta);
bool ReadSuperBackupVBMeta(int fd, SuperVBMeta* vbmeta, uint64_t super_vbmeta_size);

uint8_t ReadDataFromSuper(int fd, uint64_t offset);

}  // namespace fs_mgr
}  // namespace android