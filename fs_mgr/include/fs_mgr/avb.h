/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef ANDROID_FS_MGR_AVB_H
#define ANDROID_FS_MGR_AVB_H

#include <memory>

#include <libavb/libavb.h>

#include "fs_mgr.h"

namespace android {
namespace fs_mgr {

enum AvbHandleStatus {
    kFsMgrAvbHandleSuccess = 0,
    kFsMgrAvbHandleHashtreeDisabled = 1,
};

struct avb_handle {
    AvbSlotVerifyData* avb_slot_verify_data;
    AvbOps* avb_ops;
    AvbHandleStatus status;
};

/* Gets AVB metadata through external/avb/libavb for all partitions:
 * AvbSlotVerifyData.vbmeta_images[] and checks their integrity
 * against the androidboot.vbmeta.{hash_alg, size, digest} values
 * from /proc/cmdline.
 *
 * Possible return values:
 *   - nullptr: any error when reading and verifying the metadata,
 *     e.g., I/O error, digest value mismatch, size mismatch, etc.
 *   - a valid handle with status kFsMgrAvbHandleHashtreeDisabled:
 *     to support the 'avbctl disable-verity' feature in Android.
 *     It's very helpful for developers to make the filesystem writable to
 *     allow replacing binaries on the device.
 *   - a valid handle with status kFsMgrAvbHandleSuccess: the metadata
 *     is verified and then can be trusted.
 */
avb_handle* AvbOpen(fstab* fstab);

void AvbClose(avb_handle* handle);

bool AvbSetup(avb_handle* handle, fstab_rec* fstab_entry, bool wait_for_verity_dev);

bool AvbHashtreeDisabled(avb_handle* handle);

using avb_handle_ptr = std::unique_ptr<avb_handle, decltype(&AvbClose)>;

}  // namespace fs_mgr
}  // namespace android

#endif /* ANDROID_FS_MGR_AVB_H */
