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

#include "libavb.h"

__BEGIN_DECLS

struct vbmeta_verify_data {
	uint64_t vbmeta_size;
	uint64_t hash_size;
	char hash_algorithm[32];
	uint8_t* hash_value;
};

struct vbmeta_descriptor_data {
	size_t num_descriptors;
	const AvbDescriptor** descriptors;
	uint8_t* vbmeta_buf;
};

int load_and_verify_main_vbmeta(struct fstab* fstab,
								struct vbmeta_descriptor_data* desc_data);

int fs_mgr_setup_avb(struct fstab_rec* fstab,
					 struct vbmeta_descriptor_data* desc_data);

__END_DECLS

#endif /* __CORE_FS_MGR_PRIV_AVB_H */
