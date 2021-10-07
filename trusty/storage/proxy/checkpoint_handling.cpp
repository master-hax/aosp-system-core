/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "checkpoint_handling.h"
#include "log.h"

#include <fstab/fstab.h>
#include <cstring>
#include <string>

namespace {

bool isCheckpointing = false;

bool checkpointStateCached = false;

}  // namespace

int is_data_checkpoint_active(bool* active) {
    if (!active) {
        ALOGE("active out parameter is null");
        return -1;
    }

    if (checkpointStateCached && !isCheckpointing) {
        *active = false;
        return 0;
    }

    android::fs_mgr::Fstab procMounts;
    bool success = android::fs_mgr::ReadFstabFromFile("/proc/mounts", &procMounts);
    if (!success) {
        ALOGE("Could not parse /proc/mounts");
        return -1;
    }

    android::fs_mgr::FstabEntry* dataEntry =
            android::fs_mgr::GetEntryForMountPoint(&procMounts, "/data");
    if (dataEntry == NULL) {
        isCheckpointing = false;
        checkpointStateCached = false;

        *active = false;
        return 0;
    }

    if (dataEntry->fs_type != "f2fs") {
        ALOGW("Checkpoint status not supported for filesystem %s", dataEntry->fs_type.c_str());
        return -1;
    }

    size_t checkpointPos = dataEntry->fs_options.find("checkpoint=");
    if (checkpointPos == std::string::npos) {
        isCheckpointing = false;
        checkpointStateCached = true;

        *active = false;
        return 0;
    }
    size_t checkpointValueStart = checkpointPos + strlen("checkpoint=");

    std::string checkpointValue =
            dataEntry->fs_options.substr(checkpointValueStart, strlen("disable"));

    isCheckpointing = (checkpointValue == std::string("disable"));
    checkpointStateCached = true;

    *active = isCheckpointing;
    return 0;
}
