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

#include <android-base/result.h>

#include "vbmeta_table_format.h"

namespace android {
namespace fs_mgr {

android::base::Result<bool> ReadVBMetaTable(int fd, uint64_t offset, VBMetaTable* table);

android::base::Result<bool> ReadPrimaryVBMetaTable(int fd, VBMetaTable* table);
android::base::Result<bool> ReadBackupVBMetaTable(int fd, VBMetaTable* table);

}  // namespace fs_mgr
}  // namespace android