
#pragma once

#include <memory>

#include <liblp/builder.h>
#include <liblp/partition_opener.h>
#include "test_partition_opener.h"

namespace android {
namespace fs_mgr {

// Helper function for a single super partition, for tests.
inline std::unique_ptr<MetadataBuilder> NewTestBuilder(const IPartitionOpener& opener,
                                            const BlockDeviceInfo& device_info,
                                            uint32_t metadata_max_size,
                                            uint32_t metadata_slot_count) {
    return MetadataBuilder::New(opener, {device_info}, device_info.partition_name, metadata_max_size,
               metadata_slot_count);
}

// Wrapper around New() with a BlockDeviceInfo that only specifies a device
// size. This is a convenience method for tests.
inline std::unique_ptr<MetadataBuilder> NewTestBuilder(const IPartitionOpener& opener,
                                            uint64_t blockdev_size, uint32_t metadata_max_size,
                                            uint32_t metadata_slot_count) {
    BlockDeviceInfo device_info(LP_METADATA_DEFAULT_PARTITION_NAME, blockdev_size, 0, 0,
                                kDefaultBlockSize);
    return NewTestBuilder(opener, device_info, metadata_max_size, metadata_slot_count);
}

// Helper function for a single super partition, for tests.
inline std::unique_ptr<MetadataBuilder> NewTestBuilder(const BlockDeviceInfo& device_info,
                                            uint32_t metadata_max_size,
                                            uint32_t metadata_slot_count) {
    return NewTestBuilder(TestPartitionOpener(), device_info, metadata_max_size, metadata_slot_count);
}

// Wrapper around New() with a BlockDeviceInfo that only specifies a device
// size. This is a convenience method for tests.
inline std::unique_ptr<MetadataBuilder> NewTestBuilder(uint64_t blockdev_size, uint32_t metadata_max_size,
                                            uint32_t metadata_slot_count) {
    BlockDeviceInfo device_info(LP_METADATA_DEFAULT_PARTITION_NAME, blockdev_size, 0, 0,
                                kDefaultBlockSize);
    return NewTestBuilder(TestPartitionOpener(), device_info, metadata_max_size, metadata_slot_count);
}

}  // namespace fs_mgr
}  // namespace android
