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
#include <liblp/liblp.h>

#define VBMETA_TAG "[libvbmeta]"
#define LWARN LOG(WARNING) << VBMETA_TAG
#define LINFO LOG(INFO) << VBMETA_TAG
#define LERROR LOG(ERROR) << VBMETA_TAG
#define PWARNING PLOG(WARNING) << VBMETA_TAG
#define PERROR PLOG(ERROR) << VBMETA_TAG

namespace android {
namespace fs_mgr {

uint64_t GetPrimaryVBMetaOffset();
uint64_t GetBackupVBMetaOffset(uint64_t super_vbmeta_size);

uint64_t ComputePartitionSize(const LpMetadata& metadata, const LpMetadataPartition& partition);

// Helpers for the vbmetas' physical offset
std::pair<uint64_t, uint64_t> GetPartitionVBMetaData(const LpMetadata& metadata,
                                                     const LpMetadataPartition& partition,
                                                     const int partition_fd,
                                                     const uint64_t partition_size);

// Helpers for the vbmetas' physical offset
std::pair<uint64_t, uint64_t> GetPartitionVBMetaData(const LpMetadata& metadata,
                                                     const LpMetadataPartition& partition,
                                                     const void* avb_footer_buffer);

bool ValidateVBMeta(int fd, uint64_t offset);
}  // namespace fs_mgr
}  // namespace android