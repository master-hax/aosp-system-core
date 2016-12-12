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

#ifndef __cplusplus
#include <stdbool.h>
#endif

#include "fs_mgr.h"

__BEGIN_DECLS

#define FS_MGR_SETUP_AVB_HASHTREE_DISABLED (-2)
#define FS_MGR_SETUP_AVB_FAIL (-1)
#define FS_MGR_SETUP_AVB_SUCCESS 0

struct vbmeta_digest_data {
    size_t vbmeta_size;
    uint32_t digest_len;
    char hash_algorithm[32];
    uint8_t* digest_value;
};

int fs_mgr_load_vbmeta_images(struct fstab* fstab);

void fs_mgr_unload_vbmeta_images();

int fs_mgr_setup_avb(struct fstab_rec* fstab_entry);

__END_DECLS

#endif /* __CORE_FS_MGR_PRIV_AVB_H */
