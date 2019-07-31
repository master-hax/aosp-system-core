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

#include <android-base/endian.h>
#include <android-base/file.h>
#include <libavb/libavb.h>

#include <libvbmeta/super_vbmeta_format.h>

namespace android {
namespace fs_mgr {

uint64_t GetPrimaryVBMetaOffset() {
    return 0;
}

uint64_t GetBackupVBMetaOffset(uint64_t super_vbmeta_size) {
    return super_vbmeta_size / 2;
}

uint64_t ComputePartitionSize(const LpMetadata& metadata, const LpMetadataPartition& partition) {
    uint64_t sectors = 0;
    for (size_t i = 0; i < partition.num_extents; i++) {
        sectors += metadata.extents[partition.first_extent_index + i].num_sectors;
    }
    return sectors * LP_SECTOR_SIZE;
}

uint64_t LogicalToPhysicalOffset(const LpMetadata& metadata, const LpMetadataPartition& partition,
                                 const uint64_t offset) {
    uint32_t first_extent = partition.first_extent_index;
    uint32_t last_extent = partition.first_extent_index + partition.num_extents;
    uint64_t sectors_sum = 0;

    for (uint32_t index = first_extent; index < last_extent; index++) {
        const LpMetadataExtent& extent = metadata.extents[index];
        if (sectors_sum * LP_SECTOR_SIZE <= offset &&
            offset < (sectors_sum + extent.num_sectors) * LP_SECTOR_SIZE) {
            uint64_t physical_offset =
                    extent.target_data * LP_SECTOR_SIZE + (offset - sectors_sum * LP_SECTOR_SIZE);
            return physical_offset;
        } else {
            sectors_sum += extent.num_sectors;
        }
    }

    // LpMetaData is located at the beginning of the super partition.
    // Zero shouldn't be any resolved physical offset so using 0 to indicate
    // failure of translation.

    return 0;
}

bool ParsePartitionAvbFooter(const void* buffer, AvbFooter* footer) {
    memcpy(footer, buffer, AVB_FOOTER_SIZE);

    if (memcmp(footer->magic, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) != 0) {
        LINFO << "AVB Footer magic Compare Failed";
        return false;
    }

    // Extract relevant fields in order to construct the Super AVB footer.
    footer->version_major = be32toh(footer->version_major);
    footer->version_minor = be32toh(footer->version_minor);
    footer->original_image_size = be64toh(footer->original_image_size);
    footer->vbmeta_offset = be64toh(footer->vbmeta_offset);
    footer->vbmeta_size = be64toh(footer->vbmeta_size);

    return true;
}

std::pair<uint64_t, uint64_t> GetPartitionVBMetaData(const LpMetadata& metadata,
                                                     const LpMetadataPartition& partition,
                                                     const int partition_fd,
                                                     const uint64_t partition_size) {
    // Get Partition AVB Footer
    if (lseek(partition_fd, partition_size - AVB_FOOTER_SIZE, SEEK_SET) < 0) {
        PERROR << "Seek failed with offset " << partition_size - AVB_FOOTER_SIZE;
        return std::pair<uint64_t, uint64_t>(0, 0);
    }

    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(AVB_FOOTER_SIZE);
    if (!android::base::ReadFully(partition_fd, buffer.get(), AVB_FOOTER_SIZE)) {
        PERROR << "Read failed";
        return std::pair<uint64_t, uint64_t>(0, 0);
    }

    std::unique_ptr<AvbFooter> footer = std::make_unique<AvbFooter>();
    if (!ParsePartitionAvbFooter(buffer.get(), footer.get())) {
        return std::pair<uint64_t, uint64_t>(0, 0);
    }

    uint64_t physical_offset = LogicalToPhysicalOffset(metadata, partition, footer->vbmeta_offset);
    uint64_t physical_size = footer->vbmeta_size;

    return std::pair<uint64_t, uint64_t>(physical_offset, physical_size);
}

std::pair<uint64_t, uint64_t> GetPartitionVBMetaData(const LpMetadata& metadata,
                                                     const LpMetadataPartition& partition,
                                                     const void* avb_footer_buffer) {
    std::unique_ptr<AvbFooter> footer = std::make_unique<AvbFooter>();
    if (!ParsePartitionAvbFooter(avb_footer_buffer, footer.get())) {
        return std::pair<uint64_t, uint64_t>(0, 0);
    }

    uint64_t physical_offset = LogicalToPhysicalOffset(metadata, partition, footer->vbmeta_offset);
    uint64_t physical_size = footer->vbmeta_size;

    return std::pair<uint64_t, uint64_t>(physical_offset, physical_size);
}

bool ValidateVBMeta(int fd, uint64_t offset) {
    if (lseek(fd, offset, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << " lseek failed";
        return false;
    }
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(AVB_MAGIC_LEN);
    if (!android::base::ReadFully(fd, buffer.get(), AVB_MAGIC_LEN)) {
        PERROR << __PRETTY_FUNCTION__ << " super read vbmeta " << AVB_MAGIC_LEN << " bytes failed";
        return false;
    }
    return memcmp(buffer.get(), AVB_MAGIC, AVB_MAGIC_LEN) == 0;
}

}  // namespace fs_mgr
}  // namespace android
