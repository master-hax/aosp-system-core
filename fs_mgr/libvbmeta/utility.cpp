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

#include "utility.h"

#include <android-base/file.h>

using android::base::Error;
using android::base::Result;

namespace android {
namespace fs_mgr {

uint64_t ComputePartitionSize(const LpMetadata& lpmetadata, const LpMetadataPartition& partition) {
    uint64_t sectors = 0;
    for (size_t i = 0; i < partition.num_extents; i++) {
        sectors += lpmetadata.extents[partition.first_extent_index + i].num_sectors;
    }
    return sectors * LP_SECTOR_SIZE;
}

uint64_t ComputeSuperSize(const LpMetadata& lpmetadata) {
    uint64_t size = 0;
    for (const auto& device : lpmetadata.block_devices) {
        size += device.size;
    }
    return size;
}

Result<uint64_t> LogicalToPhysicalOffset(const LpMetadata& lpmetadata,
                                         const LpMetadataPartition& partition,
                                         const uint64_t offset) {
    uint32_t first_extent = partition.first_extent_index;
    uint32_t last_extent = partition.first_extent_index + partition.num_extents;
    uint64_t sectors_sum = 0;

    for (uint32_t index = first_extent; index < last_extent; index++) {
        const LpMetadataExtent& extent = lpmetadata.extents[index];
        if (sectors_sum * LP_SECTOR_SIZE <= offset &&
            offset < (sectors_sum + extent.num_sectors) * LP_SECTOR_SIZE) {
            uint64_t physical_offset =
                    extent.target_data * LP_SECTOR_SIZE + (offset - sectors_sum * LP_SECTOR_SIZE);

            if (physical_offset < 0 || physical_offset >= ComputeSuperSize(lpmetadata)) {
                return Error() << "physical offset is out of super partition";
            }

            return physical_offset;
        } else {
            sectors_sum += extent.num_sectors;
        }
    }

    return Error() << "logical to physical offset translation failed";
}

Result<bool> ParsePartitionAvbFooter(const void* buffer, AvbFooter* footer) {
    if (!avb_footer_validate_and_byteswap((const AvbFooter*)buffer, footer)) {
        return Error() << "AVB footer verification failed";
    }
    return true;
}

Result<std::unique_ptr<AvbFooter>> LoadAvbFooter(const int partition_fd,
                                                 const uint64_t partition_size) {
    const uint64_t offset = partition_size - AVB_FOOTER_SIZE;
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(AVB_FOOTER_SIZE);
    if (!android::base::ReadFullyAtOffset(partition_fd, buffer.get(), AVB_FOOTER_SIZE, offset)) {
        return Error() << "Couldn't read AVB footer at offset " << offset;
    }

    std::unique_ptr<AvbFooter> footer = std::make_unique<AvbFooter>();
    Result<bool> parse_partition_avbfooter =
            ParsePartitionAvbFooter((const void*)buffer.get(), footer.get());
    if (!parse_partition_avbfooter) {
        return parse_partition_avbfooter.error();
    }

    return footer;
}

Result<std::unique_ptr<VBMetaInfo>> BuildPhysicalVBMetaInfo(const LpMetadata& lpmetadata,
                                                            const LpMetadataPartition& lppartition,
                                                            const AvbFooter& avbfooter) {
    Result<uint64_t> physical_offset =
            LogicalToPhysicalOffset(lpmetadata, lppartition, avbfooter.vbmeta_offset);
    if (!physical_offset) {
        return physical_offset.error();
    }

    std::unique_ptr<VBMetaInfo> info = std::make_unique<VBMetaInfo>();
    info->vbmeta_offset = physical_offset.value();
    info->vbmeta_size = avbfooter.vbmeta_size;
    info->partition_name = std::string(lppartition.name);
    return info;
}

Result<bool> ValidateVBMeta(int fd, uint64_t offset, uint64_t size) {
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);
    if (!android::base::ReadFullyAtOffset(fd, buffer.get(), size, offset)) {
        return Error() << "Read vbmeta at " << offset << " failed";
    }
    if (avb_vbmeta_image_verify(buffer.get(), size, NULL, NULL) != AVB_VBMETA_VERIFY_RESULT_OK) {
        return Error() << "AVB vbmeta verification failed";
    }
    return true;
}

}  // namespace fs_mgr
}  // namespace android
