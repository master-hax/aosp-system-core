/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <fs_mgr/slotselect.h>

#include <stdio.h>

#include <string>

#include "fs_mgr.h"
#include "fs_mgr_priv.h"

namespace android {
namespace fs_mgr {

// Returns "_a" or "_b" based on two possible values in kernel cmdline:
//   - androidboot.slot = a or b OR
//   - androidboot.slot_suffix = _a or _b
// TODO: remove slot_suffix once it's deprecated.
std::string GetSlotSuffix() {
    std::string slot;
    std::string ab_suffix;

    if (fs_mgr_get_boot_config("slot", &slot)) {
        ab_suffix = "_" + slot;
    } else if (!fs_mgr_get_boot_config("slot_suffix", &ab_suffix)) {
        ab_suffix = "";
    }
    return ab_suffix;
}

}  // namespace fs_mgr
}  // namespace android

// Updates |fstab| for slot_suffix. Returns true on success, false on error.
bool fs_mgr_update_for_slotselect(struct fstab* fstab) {
    int n;
    bool got_suffix = false;
    std::string ab_suffix;

    for (n = 0; n < fstab->num_entries; n++) {
        if (fstab->recs[n].fs_mgr_flags & MF_SLOTSELECT) {
            char *tmp;
            if (!got_suffix) {
                ab_suffix = android::fs_mgr::GetSlotSuffix();
                if (ab_suffix.empty()) return false;
                got_suffix = true;
            }
            if (asprintf(&tmp, "%s%s", fstab->recs[n].blk_device, ab_suffix.c_str()) > 0) {
                free(fstab->recs[n].blk_device);
                fstab->recs[n].blk_device = tmp;
            } else {
                return false;
            }
        }
    }
    return true;
}
