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
#include <android-base/strings.h>
#include <liblp/liblp.h>

using android::base::ErrnoError;
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
        return ErrnoError() << "Couldn't read AVB footer at offset " << offset;
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

Result<bool> CheckPartitionIsSelfSigned(const std::string& vbmeta_name,
                                        const std::string& slot_suffix,
                                        const std::string& partition_name) {
    const IPartitionOpener& opener = PartitionOpener();

    BlockDeviceInfo info;
    if (!opener.GetInfo(vbmeta_name, &info)) {
        return ErrnoError() << "Couldn't get vbmeta info of " << vbmeta_name;
    }

    android::base::unique_fd fd = opener.Open(vbmeta_name, O_RDONLY);
    if (fd < 0) {
        return ErrnoError() << "Couldn't open vbmeta " << vbmeta_name;
    }

    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(info.size);
    if (!android::base::ReadFully(fd, buffer.get(), info.size)) {
        return ErrnoError() << "Couldn't read vbmeta " << vbmeta_name;
    }

    size_t num_descriptors;
    auto descriptors = avb_descriptor_get_all(buffer.get(), info.size, &num_descriptors);
    for (size_t n = 0; n < num_descriptors; n++) {
        AvbDescriptor desc;
        if (!avb_descriptor_validate_and_byteswap(descriptors[n], &desc)) {
            return Error() << "vbmeta descriptor is invalid";
        }
        switch (desc.tag) {
            case AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: {
                AvbChainPartitionDescriptor chain_desc;
                if (!avb_chain_partition_descriptor_validate_and_byteswap(
                            (AvbChainPartitionDescriptor*)descriptors[n], &chain_desc)) {
                    return Error() << "chain partition descriptor is invalid";
                }
                std::string chain_partition_name(
                        (const char*)descriptors[n] + sizeof(AvbChainPartitionDescriptor),
                        chain_desc.partition_name_len);
                if (partition_name == chain_partition_name) {
                    return true;
                } else if (android::base::StartsWith(chain_partition_name, "vbmeta_")) {
                    Result<bool> partition_is_self_signed = CheckPartitionIsSelfSigned(
                            chain_partition_name + slot_suffix, slot_suffix, partition_name);
                    if (partition_is_self_signed) {
                        return partition_is_self_signed.value();
                    }
                }
            } break;
            case AVB_DESCRIPTOR_TAG_HASHTREE: {
                AvbHashtreeDescriptor hashtree_desc;
                if (!avb_hashtree_descriptor_validate_and_byteswap(
                            (AvbHashtreeDescriptor*)descriptors[n], &hashtree_desc)) {
                    return Error() << "hashtree partition descriptor is invalid";
                }
                std::string hashtree_partition_name(
                        (const char*)descriptors[n] + sizeof(AvbHashtreeDescriptor),
                        hashtree_desc.partition_name_len);
                if (partition_name == hashtree_partition_name) {
                    return false;
                }
            } break;
        }
    }

    return Error() << "Couldn't find " << partition_name << " in vbmeta";
}

Result<bool> ValidateVBMeta(int fd, uint64_t offset, uint64_t size) {
    return ValidateVBMetaWithResult(fd, offset, size, AVB_VBMETA_VERIFY_RESULT_OK);
}

Result<bool> ValidateVBMetaWithResult(int fd, uint64_t offset, uint64_t size,
                                      AvbVBMetaVerifyResult result) {
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);
    if (!android::base::ReadFullyAtOffset(fd, buffer.get(), size, offset)) {
        return ErrnoError() << "Read vbmeta at " << offset << " failed";
    }
    AvbVBMetaVerifyResult ret = avb_vbmeta_image_verify(buffer.get(), size, NULL, NULL);
    if (ret != result) {
        return Error() << "AVB vbmeta verification " << avb_vbmeta_verify_result_to_string(result)
                       << " failed " << avb_vbmeta_verify_result_to_string(ret);
    }
    return true;
}

}  // namespace fs_mgr
}  // namespace android
