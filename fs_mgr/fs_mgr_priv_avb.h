/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef __CORE_FS_MGR_PRIV_AVB_H
#define __CORE_FS_MGR_PRIV_AVB_H

#include <libavb/libavb.h>
#include "fs_mgr.h"

enum AvbHandleStatus {
    kFsMgrAvbHandleSuccess = 0,
    kFsMgrAvbHandleHashtreeDisabled = 1,
};

struct fs_mgr_avb_handle {
    AvbSlotVerifyData* avb_slot_verify_data;
    AvbOps* avb_ops;
    AvbHandleStatus status;
    std::string avb_version;
};

/* Gets AVB metadata through external/avb/libavb for all partitions:
 * AvbSlotVerifyData.vbmeta_images[] and checks their integrity
 * against the androidboot.vbmeta.{hash_alg, size, digest} values
 * from /proc/cmdline.
 *
 * Possible values of out_result:
 *   - kFsMgrAvbHandleSuccess: the metadata cab be trusted, and a
 *     fs_mgr_avb_handle will be returned.
 *   - kFsMgrAvbHandleFail: any error when reading and verifying the
 *     metadata, e.g. I/O error, digest value mismatch, size mismatch.
 *   - kFsMgrAvbHandleHashtreeDisabled: to support the existing
 *     'adb disable-verity' feature in Android. It's very helpful for
 *     developers to make the filesystem writable to allow replacing
 *     binaries on the device.
 */
fs_mgr_avb_handle* fs_mgr_avb_open(fstab* fstab);

void fs_mgr_avb_close(fs_mgr_avb_handle* handle);

bool fs_mgr_setup_avb(fs_mgr_avb_handle* handle, fstab_rec* fstab_entry);

#endif /* __CORE_FS_MGR_PRIV_AVB_H */
