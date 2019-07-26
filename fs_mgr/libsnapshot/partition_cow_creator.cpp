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

#include "utility.h"

namespace android {
namespace snapshot {

// Round |d| up to a multiple of |block_size|.
static uint64_t RoundUp(double d, uint64_t block_size) {
    uint64_t ret = ((uint64_t)ceil(d) + block_size - 1) / block_size * block_size;
    CHECK(ret >= d) << "Can't round " << d << " up to a multiple of " << block_size;
    return ret;
}

// Intersect two linear extents. If no intersection, return an extent with length 0.
static std::unique_ptr<fs_mgr::Extent> Intersect(fs_mgr::Extent* target_extent,
                                                 fs_mgr::Extent* existing_extent) {
    // Convert target_extent and existing_extent to linear extents. Zero extents
    // doesn't matter and doesn't result in any intersection.
    auto existing_linear_extent = existing_extent->AsLinearExtent();
    if (!existing_extent) return std::make_unique<fs_mgr::ZeroExtent>(0);

    auto target_linear_extent = target_extent->AsLinearExtent();
    if (!target_linear_extent) return std::make_unique<fs_mgr::ZeroExtent>(0);

    return android::fs_mgr::Interval::Intersect(
        target_linear_extent->AsInterval(), existing_linear_extent->AsInterval()).AsExtent();
}

// Check that partition |p| contains |e| fully. Both of them should
// be from |target_metadata|.
// Returns true as long as |e| is a subrange of any extent of |p|.
bool PartitionCowCreator::HasExtent(fs_mgr::Partition* p, fs_mgr::Extent* e) {
    for (auto& partition_extent : p->extents()) {
        auto intersection = Intersect(partition_extent.get(), e);
        if (intersection->num_sectors() == e->num_sectors()) return true;
    }
    return false;
}

// Return the number of sectors, N, where |target_partition|[0..N] (from
// |target_metadata|) are the sectors that should be snapshotted. N is computed
// so that this range of sectors are used by partitions in |current_metadata|.
//
// The client code (update_engine) should have computed target_metadata by
// resizing partitions of current_metadata, so only the first N sectors should
// be snapshotted, not a range with start index != 0.
std::optional<uint64_t> PartitionCowCreator::GetSnapshotSize() {
    // Compute the number of sectors that needs to be snapshotted.
    uint64_t snapshot_sectors = 0;
    std::vector<std::unique_ptr<fs_mgr::Extent>> intersections;
    for (const auto& extent : target_partition->extents()) {
        ForEachPartition(current_metadata, current_suffix, [&](auto* existing_partition) {
            for (const auto& existing_extent : existing_partition->extents()) {
                auto intersection = Intersect(extent.get(), existing_extent.get());
                if (intersection->num_sectors() > 0) {
                    snapshot_sectors += intersection->num_sectors();
                    intersections.emplace_back(std::move(intersection));
                }
            }
            return LoopDirective::CONTINUE;
        });
    }

    // Align snapshot_sectors with logical_block_size and LP_SECTOR_SIZE.
    uint64_t snapshot_size = snapshot_sectors * LP_SECTOR_SIZE;

    // Sanity check that all recorded intersections are indeed within
    // target_partition[0..snapshot_sectors].
    fs_mgr::Partition target_partition_snapshot =
            target_partition->GetBeginningExtents(snapshot_size);
    for (const auto& intersection : intersections) {
        if (!HasExtent(&target_partition_snapshot, intersection.get())) {
            auto linear_intersection = intersection->AsLinearExtent();
            LOG(ERROR)
                    << "Extent "
                    << (linear_intersection
                                ? (std::to_string(linear_intersection->physical_sector()) +
                                   "," + std::to_string(linear_intersection->end_sector()))
                                : "")
                    << " is not part of Partition " << target_partition->name() << "[0.."
                    << snapshot_size
                    << "]. The metadata wasn't constructed correctly. This should not happen.";
            return std::nullopt;
        }
    }

    return snapshot_size;
}

std::optional<PartitionCowCreator::Return> PartitionCowCreator::operator()() {
    static constexpr double kCowEstimateFactor = 1.1;

    CHECK(current_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME &&
          target_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME);

    Return ret;
    ret.snapshot_status.device_size = target_partition->size();

    auto snapshot_size = GetSnapshotSize();
    if (!snapshot_size.has_value()) return std::nullopt;

    ret.snapshot_status.snapshot_size = *snapshot_size;

    // TODO: always read from cow_size when the COW size is written in
    // update package. kCowEstimateFactor is good for prototyping but
    // we can't use that in production.
    if (!cow_size.has_value()) {
        cow_size = RoundUp(ret.snapshot_status.snapshot_size * kCowEstimateFactor,
                           fs_mgr::kDefaultBlockSize);
    }

    // TODO: create COW partition in target_metadata to save space.
    ret.snapshot_status.cow_partition_size = 0;
    ret.snapshot_status.cow_file_size = (*cow_size) - ret.snapshot_status.cow_partition_size;

    return ret;
}

}  // namespace snapshot
}  // namespace android
