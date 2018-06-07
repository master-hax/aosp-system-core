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

#ifndef LIBLP_WRITER_H
#define LIBLP_WRITER_H

#include "metadata_format.h"

namespace android {
namespace fs_mgr {

// We store two copies of the logical partition metadata: a primary copy at
// the first sector, and a backup copy in the last sectors. It is possible
// to only write one copy at a time, e.g. for A/B or to ensure that the first
// copy can be read back before proceeding.
enum class SyncMode {
    // Overwrite all copies.
    Flash,
    // Only update the backup copy.
    Backup,
    // Only update the primary copy.
    Primary
};

// Write the given partition table to the given block device, writing only
// copies according to the given sync mode.
//
// This will perform some verification, such that the device has enough space
// to store the metadata as well as all of its extents.
bool WritePartitionTable(const char* block_device, const LpMetadata& metadata, SyncMode sync_mode);

// Serialize metadata to a file, for upload to a device.
bool WriteToFile(const char* file, const LpMetadata& metadata);

}  // namespace fs_mgr
}  // namespace android

#endif /* LIBLP_WRITER_H */
