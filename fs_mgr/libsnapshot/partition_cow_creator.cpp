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
using android::fs_mgr::LinearExtent;
using android::fs_mgr::Partition;
using chromeos_update_engine::InstallOperation;
template <typename T>
using RepeatedPtrField = google::protobuf::RepeatedPtrField<T>;

namespace android {
namespace snapshot {

// Round |d| up to a multiple of |block_size|.
static uint64_t RoundUp(double d, uint64_t block_size) {
    uint64_t ret = ((uint64_t)ceil(d) + block_size - 1) / block_size * block_size;
    CHECK(ret >= d) << "Can't round " << d << " up to a multiple of " << block_size;
    return ret;
}

// Intersect two linear extents. If no intersection, return an extent with length 0.
static std::unique_ptr<LinearExtent> Intersect(Extent* target_extent, Extent* existing_extent) {
    // Convert target_extent and existing_extent to linear extents. Zero extents
    // doesn't matter and doesn't result in any intersection.
    auto existing_linear_extent = existing_extent->AsLinearExtent();
    if (!existing_linear_extent) return nullptr;

    auto target_linear_extent = target_extent->AsLinearExtent();
    if (!target_linear_extent) return nullptr;

    return Interval::Intersect(target_linear_extent->AsInterval(),
                               existing_linear_extent->AsInterval())
            .AsLinearExtent();
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

// Return the list of extents that needs to be snapshotted. The order of these
// ranges does not matter, but it is sorted based on the start sector so that
// they can be merged later.
PartitionCowCreator::SortedLinearExtents PartitionCowCreator::GetSnapshotRanges() {
    SortedLinearExtents snapshot_extents(
            [](const auto& a, const auto& b) { return a.physical_sector() < b.physical_sector(); });

    // Offset (in sectors) of |target_extent| into the logical partition.
    uint64_t extent_offset = 0;
    for (const auto& target_extent : target_partition->extents()) {
        auto* target_linear_extent = target_extent->AsLinearExtent();
        if (!target_linear_extent) {
            extent_offset += target_extent->num_sectors();
            continue;
        }

        for (auto* existing_partition :
             ListPartitionsWithSuffix(current_metadata, current_suffix)) {
            for (const auto& existing_extent : existing_partition->extents()) {
                auto intersection = Intersect(target_linear_extent, existing_extent.get());

                if (intersection == nullptr || intersection->num_sectors() == 0) {
                    continue;
                }

                // Offset (in sectors) of |intersection| into the logical partition.
                uint64_t interval_offset = intersection->physical_sector() -
                                           target_linear_extent->physical_sector() + extent_offset;

                snapshot_extents.emplace(intersection->num_sectors(), 0 /* device_index */,
                                         interval_offset);
            }
        }
        extent_offset += target_extent->num_sectors();
    }
    DCHECK(extent_offset * kSectorSize == target_partition->size());

    return snapshot_extents;
}

// Merge the list of extents that needs to be snapshotted.
std::vector<LinearExtent> PartitionCowCreator::MergeSnapshotRanges(
        const SortedLinearExtents& snapshot_extents) {
    std::vector<LinearExtent> merged_extents;
    // Add a sentinal node at the beginning to simplify the algorithm.
    merged_extents.emplace_back(0, 0, 0);
    for (const LinearExtent& snapshot_extent : snapshot_extents) {
        auto& last_extent = merged_extents.back();

        auto physical_sector = snapshot_extent.physical_sector();
        auto end_sector = snapshot_extent.end_sector();

        DCHECK(last_extent.physical_sector() <= physical_sector);

        // Try to merge with last_extent.
        if (physical_sector <= last_extent.end_sector()) {
            if (end_sector > last_extent.end_sector()) {
                last_extent = LinearExtent(end_sector - last_extent.physical_sector(), 0,
                                           last_extent.physical_sector());
            }
            continue;
        }

        merged_extents.emplace_back(end_sector - physical_sector /* num_sectors */,
                                    0 /* device_index */, physical_sector);
    }
    return merged_extents;
}

// Calculate the ranges into the logical |target_partition| that needs to be
// snapshotted.
//
// Note that if partition A has shrunk and partition B has grown, the new
// extents of partition B may use the empty space that was used by partition A.
// In this case, that new extent cannot be written directly, as it may be used
// by the running system. Hence, all extents of the new partition B must be
// intersected with all old partitions (including old partition A and B) to get
// the region that needs to be snapshotted.
//
// After this function is called, |snapshot_size| and |snapshot_intervals| will
// be set.
void PartitionCowCreator::CalculateSnapshotRanges(SnapshotStatus* snapshot_status) {
    auto snapshot_extents = GetSnapshotRanges();
    auto merged_extents = MergeSnapshotRanges(snapshot_extents);

    // Transform into the list of SnapshotInterval.
    uint64_t total_snapshot_sectors = 0;
    for (const auto& snapshot_extent : merged_extents) {
        if (snapshot_extent.num_sectors() == 0) {
            // Skip the sentinel node if necessary.
            continue;
        }
        auto* snapshot_interval = snapshot_status->add_snapshot_intervals();
        DCHECK(snapshot_extent.physical_sector() * kSectorSize <= target_partition->size());
        DCHECK(snapshot_extent.end_sector() * kSectorSize <= target_partition->size());
        snapshot_interval->set_offset(snapshot_extent.physical_sector() * kSectorSize);
        snapshot_interval->set_length(snapshot_extent.num_sectors() * kSectorSize);
        total_snapshot_sectors += snapshot_extent.num_sectors();
    }
    snapshot_status->set_snapshot_size(total_snapshot_sectors * kSectorSize);
}

std::optional<uint64_t> PartitionCowCreator::GetCowSize(uint64_t snapshot_size) {
    // TODO: Use |operations|. to determine a minimum COW size.
    // kCowEstimateFactor is good for prototyping but we can't use that in production.
    static constexpr double kCowEstimateFactor = 1.05;
    auto cow_size = RoundUp(snapshot_size * kCowEstimateFactor, kDefaultBlockSize);
    return cow_size;
}

std::optional<PartitionCowCreator::Return> PartitionCowCreator::Run() {
    CHECK(current_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME &&
          target_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME);

    uint64_t logical_block_size = current_metadata->logical_block_size();
    CHECK(logical_block_size != 0 && !(logical_block_size & (logical_block_size - 1)))
            << "logical_block_size is not power of 2";

    Return ret;
    ret.snapshot_status.set_name(target_partition->name());
    ret.snapshot_status.set_device_size(target_partition->size());

    CalculateSnapshotRanges(&ret.snapshot_status);

    auto cow_size = GetCowSize(ret.snapshot_status.snapshot_size());
    if (!cow_size.has_value()) return std::nullopt;

    // Compute regions that are free in both current and target metadata. These are the regions
    // we can use for COW partition.
    auto target_free_regions = target_metadata->GetFreeRegions();
    auto current_free_regions = current_metadata->GetFreeRegions();
    auto free_regions = Interval::Intersect(target_free_regions, current_free_regions);
    uint64_t free_region_length = 0;
    for (const auto& interval : free_regions) {
        free_region_length += interval.length() * kSectorSize;
    }

    LOG(INFO) << "Remaining free space for COW: " << free_region_length << " bytes";

    // Compute the COW partition size.
    uint64_t cow_partition_size = std::min(*cow_size, free_region_length);
    // Round it down to the nearest logical block. Logical partitions must be a multiple
    // of logical blocks.
    cow_partition_size &= ~(logical_block_size - 1);
    ret.snapshot_status.set_cow_partition_size(cow_partition_size);
    // Assign cow_partition_usable_regions to indicate what regions should the COW partition uses.
    ret.cow_partition_usable_regions = std::move(free_regions);

    // The rest of the COW space is allocated on ImageManager.
    uint64_t cow_file_size = (*cow_size) - ret.snapshot_status.cow_partition_size();
    // Round it up to the nearest sector.
    cow_file_size += kSectorSize - 1;
    cow_file_size &= ~(kSectorSize - 1);
    ret.snapshot_status.set_cow_file_size(cow_file_size);

    return ret;
}

}  // namespace snapshot
}  // namespace android
