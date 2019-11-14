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

#include <android-base/unique_fd.h>
#include <linux/fiemap.h>

// Some implementation details exposed to pin_test.cpp

namespace android::f2fs_pin {

//  The hardwired block size of all F2FS file systems.

constexpr off_t kF2fsBlockSize = 4 * 1024;  // f2fs block size

typedef struct fiemap Fiemap;
typedef struct fiemap_extent FiemapExtent;

struct ExtentMap {
    Fiemap em_fiemap;
    FiemapExtent em_extents[1];
};

typedef android::base::Result<ExtentMap> ResultExtentMap;

ResultExtentMap FileGetExtentMap(int file_fd, off_t offset, off_t length);
Result FiemapExtentValidate(const FiemapExtent& fe);

};  // namespace android::f2fs_pin
