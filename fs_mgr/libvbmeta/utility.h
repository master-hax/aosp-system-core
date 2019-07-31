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

#include <android-base/logging.h>
#include <android-base/result.h>
#include <libavb/libavb.h>
#include <liblp/liblp.h>

#include "vbmeta_table_format.h"

#define VBMETA_TAG "[libvbmeta]"
#define LWARN LOG(WARNING) << VBMETA_TAG
#define LINFO LOG(INFO) << VBMETA_TAG
#define LERROR LOG(ERROR) << VBMETA_TAG
#define PWARNING PLOG(WARNING) << VBMETA_TAG
#define PERROR PLOG(ERROR) << VBMETA_TAG

namespace android {
namespace fs_mgr {

uint64_t ComputePartitionSize(const LpMetadata& lpmetadata, const LpMetadataPartition& partition);

uint64_t ComputeSuperSize(const LpMetadata& lpmetadata);

// Helper to parse partition AVB Footer
android::base::Result<bool> ParsePartitionAvbFooter(const void* buffer, AvbFooter* footer);

// Helper to load avb footer, it reads the partition file by |partition_fd|
// and seek to the position of avbfooter by |partition_size|.
android::base::Result<std::unique_ptr<AvbFooter>> LoadAvbFooter(const int partition_fd,
                                                                const uint64_t partition_size);

// Helper to build physical VBMetaInfo, it use avbfooter to get the logical address and the size of
// vbmeta and calculate the physical address by |lpmetadata| and |lppartition|.
android::base::Result<std::unique_ptr<VBMetaInfo>> BuildPhysicalVBMetaInfo(
        const LpMetadata& lpmetadata, const LpMetadataPartition& lppartition,
        const AvbFooter& avbfooter);

// Helper to validate vbmeta, which is |size| bytes at |offset| in file |fd|.
android::base::Result<bool> ValidateVBMeta(int fd, uint64_t offset, uint64_t size);
}  // namespace fs_mgr
}  // namespace android