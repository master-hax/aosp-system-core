// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "partition_cow_creator.h"

#include <math.h>

#include <android-base/logging.h>

#include <android/snapshot/snapshot.pb.h>
#include "utility.h"

using android::dm::kSectorSize;
using android::fs_mgr::Extent;
using android::fs_mgr::Interval;
using android::fs_mgr::kDefaultBlockSize;
using android::fs_mgr::Partition;
using chromeos_update_engine::InstallOperation;
template <typename T>
using RepeatedPtrField = google::protobuf::RepeatedPtrField<T>;

namespace android {
namespace snapshot {

// Intersect two linear extents. If no intersection, return an extent with length 0.
static std::unique_ptr<Extent> Intersect(Extent* target_extent, Extent* existing_extent) {
    // Convert target_extent and existing_extent to linear extents. Zero extents
    // doesn't matter and doesn't result in any intersection.
    auto existing_linear_extent = existing_extent->AsLinearExtent();
    if (!existing_linear_extent) return nullptr;

    auto target_linear_extent = target_extent->AsLinearExtent();
    if (!target_linear_extent) return nullptr;

    return Interval::Intersect(target_linear_extent->AsInterval(),
                               existing_linear_extent->AsInterval())
            .AsExtent();
}

// Check that partition |p| contains |e| fully. Both of them should
// be from |target_metadata|.
// Returns true as long as |e| is a subrange of any extent of |p|.
bool PartitionCowCreator::HasExtent(Partition* p, Extent* e) {
    for (auto& partition_extent : p->extents()) {
        auto intersection = Intersect(partition_extent.get(), e);
        if (intersection != nullptr && intersection->num_sectors() == e->num_sectors()) {
            return true;
        }
    }
    return false;
}

uint64_t PartitionCowCreator::GetCowSize(const SnapshotStatus& snapshot_status) {
    // The origin partition should be read-only

    if (operations == nullptr) {
        // Compatibility mode for COW size computation: no operations on the
        // COW file are specified, so it's not possible to know in advance the
        // smallest snapshot size.
        // What this function returns in this case is then the size of the
        // snapshot itself.
        LOG(WARNING) << "Test path for GetCowSize without operations";
        return snapshot_status.snapshot_size();
    }

    uint64_t highest_modified_block = 0;
    for (const auto& iop : *operations) {
        for (const auto& de : iop.dst_extents()) {
            highest_modified_block =
                    std::max(de.start_block() + de.num_blocks(), highest_modified_block);
        }
    }

    return highest_modified_block * kDefaultBlockSize;
}

class DmSnapCoWSizeCalculator {
  public:
    DmSnapCoWSizeCalculator(unsigned int sector_bytes, unsigned int chunk_sectors)
        : sector_bytes_(sector_bytes),
          chunk_sectors_(chunk_sectors),
          exceptions_per_chunk(chunk_sectors_ * sector_bytes_ / (64 * 2 / 8)) {}

    void write_byte(uint64_t address) { write_sector(address / sector_bytes_); }
    void write_sector(uint64_t sector) { write_chunk(sector / chunk_sectors_); }
    void write_chunk(uint64_t chunk_id) { disk_chunks_writes_.insert(chunk_id); }

    uint64_t cow_size_bytes() const { return cow_size_sectors() * sector_bytes_; }
    uint64_t cow_size_sectors() const { return cow_size_chunks() * chunk_sectors_; }
    uint64_t cow_size_chunks() const {
        const uint64_t modified_chunks = disk_chunks_writes_.size();
        uint64_t cow_chunks = 0;

        /* disk header + padding = 1 chunk */
        cow_chunks += 1;

        /* snapshot modified data */
        cow_chunks += modified_chunks;

        /* snapshot chunks metadata */
        cow_chunks += 1 + modified_chunks / exceptions_per_chunk;

        return cow_chunks;
    }

  private:
    const uint64_t sector_bytes_;
    const uint64_t chunk_sectors_;
    const uint64_t exceptions_per_chunk;
    std::set<uint64_t> disk_chunks_writes_;
};

uint64_t PartitionCowCreator::GetCowFileSize(const SnapshotStatus& snapshot_status) {
    const uint64_t logical_block_size = current_metadata->logical_block_size();
    const uint64_t snapshot_blocks = snapshot_status.snapshot_size() / logical_block_size;
    DmSnapCoWSizeCalculator sc(logical_block_size, kSnapshotChunkSize);

    if (operations != nullptr) {
        for (const auto& iop : *operations) {
            for (const auto& de : iop.dst_extents()) {
                // Skip if blocks are written
                if (de.num_blocks() == 0) continue;
                // Skip if the operation modifies only the free region
                if (de.start_block() > snapshot_blocks) continue;

                const auto block_boundary =
                        std::min(de.start_block() + de.num_blocks(), snapshot_blocks);
                for (auto b = de.start_block(); b < block_boundary; ++b) {
                    sc.write_sector(b);
                }
            }
        }
    }

    return sc.cow_size_bytes();
}

std::optional<PartitionCowCreator::Return> PartitionCowCreator::Run() {
    CHECK(current_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME &&
          target_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME);

    const uint64_t logical_block_size = current_metadata->logical_block_size();
    CHECK(logical_block_size != 0 && !(logical_block_size & (logical_block_size - 1)))
            << "logical_block_size is not power of 2";

    Return ret;
    ret.snapshot_status.set_name(target_partition->name());
    ret.snapshot_status.set_device_size(target_partition->size());
    ret.snapshot_status.set_snapshot_size(target_partition->size());

    // Being the COW partition virtual, its size doesn't affect the storage
    // memory that will be occupied by the target.
    // The actual storage space is affected by the COW file, whose size depends
    // on the chunks that diverged between |current| and |target|.
    // If the |target| partition is bigger than |current|, the data that is
    // modified outside of |current| can be written directly to |current|.
    // This because the data that will be written outside of |current| would
    // not invalidate any useful information of |current|, thus:
    // - if the snapshot is accepted for merge, this data would be already at
    // the right place and should not be copied;
    // - in the unfortunate case of the snapshot to be discarded, the regions
    // modified by this data can be set as free regions and reused.
    // Compute regions that are free in both current and target metadata. These are the regions
    // we can use for COW partition.
    auto target_free_regions = target_metadata->GetFreeRegions();
    auto current_free_regions = current_metadata->GetFreeRegions();
    auto free_regions = Interval::Intersect(target_free_regions, current_free_regions);
    uint64_t free_region_length = 0;
    for (const auto& interval : free_regions) {
        free_region_length += interval.length();
    }
    free_region_length *= kSectorSize;

    LOG(INFO) << "Remaining free space for COW: " << free_region_length << " bytes";
    auto cow_size = GetCowSize(ret.snapshot_status);

    // Compute the COW partition size.
    uint64_t cow_partition_size = std::min(cow_size, free_region_length);
    // Round it down to the nearest logical block. Logical partitions must be a multiple
    // of logical blocks.
    cow_partition_size &= ~(logical_block_size - 1);
    ret.snapshot_status.set_cow_partition_size(cow_partition_size);
    // Assign cow_partition_usable_regions to indicate what regions should the COW partition uses.
    ret.cow_partition_usable_regions = std::move(free_regions);

    auto cow_file_size = GetCowFileSize(ret.snapshot_status);
    // Round it up to the nearest sector.
    cow_file_size += kSectorSize - 1;
    cow_file_size &= ~(kSectorSize - 1);
    ret.snapshot_status.set_cow_file_size(cow_file_size);

    return ret;
}

}  // namespace snapshot
}  // namespace android
