/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include "lp/builder.h"

#include <assert.h>
#include <string.h>

#include <algorithm>

#include <android-base/endian.h>

#include "lp/metadata_format.h"
#include "lp_utility.h"

namespace android {
namespace fs_mgr {

// Align a byte count up to the nearest 512-byte sector.
template <typename T>
static inline T AlignToSector(T value) {
    return (value + (LP_SECTOR_SIZE - 1)) & ~T(LP_SECTOR_SIZE - 1);
}

void LinearExtent::AddTo(LpMetadata* out) const {
    out->extents.push_back(LpMetadataExtent{num_sectors_, LP_TARGET_TYPE_LINEAR, physical_sector_});
}

void ZeroExtent::AddTo(LpMetadata* out) const {
    out->extents.push_back(LpMetadataExtent{num_sectors_, LP_TARGET_TYPE_ZERO, 0});
}

Partition::Partition(const std::string& name, const uint8_t guid[16], uint32_t attributes)
    : name_(name), attributes_(attributes), size_(0) {
    memcpy(guid_, guid, sizeof(guid_));
}

void Partition::AddExtent(std::unique_ptr<Extent>&& extent) {
    size_ += extent->num_sectors() * LP_SECTOR_SIZE;
    extents_.push_back(std::move(extent));
}

void Partition::RemoveExtents() {
    size_ = 0;
    extents_.clear();
}

void Partition::ShrinkTo(uint64_t requested_size) {
    uint64_t aligned_size = AlignToSector(requested_size);
    if (size_ <= aligned_size) {
        return;
    }
    if (aligned_size == 0) {
        RemoveExtents();
        return;
    }

    // Remove or shrink extents of any kind until the total partition size is
    // equal to the requested size.
    uint64_t sectors_to_remove = (size_ - aligned_size) / LP_SECTOR_SIZE;
    while (sectors_to_remove) {
        Extent* extent = extents_.back().get();
        if (extent->num_sectors() > sectors_to_remove) {
            size_ -= sectors_to_remove * LP_SECTOR_SIZE;
            extent->set_num_sectors(extent->num_sectors() - sectors_to_remove);
            break;
        }
        size_ -= (extent->num_sectors() * LP_SECTOR_SIZE);
        sectors_to_remove -= extent->num_sectors();
        extents_.pop_back();
    }
    assert(size_ == requested_size);
}

std::unique_ptr<MetadataBuilder> MetadataBuilder::New(uint64_t blockdevice_size,
                                                      uint32_t metadata_reserved) {
    std::unique_ptr<MetadataBuilder> builder(new MetadataBuilder());
    if (!builder->Init(blockdevice_size, metadata_reserved)) {
        return nullptr;
    }
    return builder;
}

std::unique_ptr<MetadataBuilder> MetadataBuilder::New(const LpMetadata& metadata) {
    std::unique_ptr<MetadataBuilder> builder(new MetadataBuilder());
    if (!builder->Init(metadata)) {
        return nullptr;
    }
    return builder;
}

MetadataBuilder::MetadataBuilder() {
    header_.magic = LP_METADATA_HEADER_MAGIC;
    header_.major_version = LP_METADATA_MAJOR_VERSION;
    header_.minor_version = LP_METADATA_MINOR_VERSION;
    header_.header_size = sizeof(header_);
    header_.partitions.entry_size = sizeof(LpMetadataPartition);
    header_.extents.entry_size = sizeof(LpMetadataExtent);
}

bool MetadataBuilder::Init(const LpMetadata& metadata) {
    for (const auto& partition : metadata.partitions) {
        std::shared_ptr<Partition> builder =
                AddPartition(GetPartitionName(partition), partition.guid, partition.attributes);
        if (!builder) {
            return false;
        }

        for (const auto& extent : metadata.extents) {
            if (extent.target_type == LP_TARGET_TYPE_LINEAR) {
                auto copy = std::make_unique<LinearExtent>(extent.num_sectors, extent.target_data);
                builder->AddExtent(std::move(copy));
            } else if (extent.target_type == LP_TARGET_TYPE_ZERO) {
                auto copy = std::make_unique<ZeroExtent>(extent.num_sectors);
                builder->AddExtent(std::move(copy));
            }
        }
    }
    return true;
}

bool MetadataBuilder::Init(uint64_t blockdevice_size, uint32_t metadata_reserved) {
    // Align the metadata size up to the nearest sector.
    metadata_reserved = AlignToSector(metadata_reserved);

    // We need space for two copies of metadata, plus a 4KB block at the end
    // to squirrel away backup headers. After taking away this space, the block
    // device must have at least one sector free for allocating logical partitions.
    uint64_t backups_size = metadata_reserved + LP_METADATA_BACKUP_BLOCK_SIZE;
    uint64_t total_reserved = metadata_reserved + backups_size;

    if (blockdevice_size < total_reserved || blockdevice_size - total_reserved < LP_SECTOR_SIZE) {
        LERROR << "Attempting to create metadata on a block device that is too small.";
        return false;
    }

    // The last sector is inclusive. We subtract one to make sure that logical
    // partitions won't overlap with the same sector as the backup metadata,
    // which could happen if the block device was not aligned to LP_SECTOR_SIZE.
    header_.first_logical_sector = metadata_reserved / LP_SECTOR_SIZE;
    header_.last_logical_sector = ((blockdevice_size - backups_size) / LP_SECTOR_SIZE) - 1;
    header_.metadata_reserved = metadata_reserved;
    assert(header_.last_logical_sector >= header_.first_logical_sector);
    return true;
}

std::shared_ptr<Partition> MetadataBuilder::AddPartition(const std::string& name,
                                                         const uint8_t guid[16],
                                                         uint32_t attributes) {
    if (name.empty()) {
        LERROR << "Partition must have a non-empty name.";
        return nullptr;
    }
    if (partition_names_.find(name) != partition_names_.end()) {
        LERROR << "Attempting to create duplication partition with name: " << name;
        return nullptr;
    }
    auto partition = std::make_shared<Partition>(name, guid, attributes);
    partitions_.push_back(partition);
    partition_names_[name] = partition;
    return partition;
}

std::shared_ptr<Partition> MetadataBuilder::FindPartition(const std::string& name) {
    auto iter = partition_names_.find(name);
    if (iter == partition_names_.end()) {
        return nullptr;
    }
    return iter->second;
}

void MetadataBuilder::RemovePartition(const std::string& name) {
    auto map_iter = partition_names_.find(name);
    if (map_iter == partition_names_.end()) {
        return;
    }
    partition_names_.erase(map_iter);

    for (auto iter = partitions_.begin(); iter != partitions_.end(); iter++) {
        if ((*iter)->name() == name) {
            partitions_.erase(iter);
            return;
        }
    }
}

bool MetadataBuilder::GrowPartition(Partition& partition, uint64_t requested_size) {
    // Align the space needed up to the nearest sector.
    uint64_t aligned_size = AlignToSector(requested_size);
    if (partition.size() >= aligned_size) {
        return true;
    }

    // Figure out how much we need to allocate.
    uint64_t space_needed = aligned_size - partition.size();
    uint64_t sectors_needed = space_needed / LP_SECTOR_SIZE;
    assert(sectors_needed * LP_SECTOR_SIZE == space_needed);

    struct Interval {
        uint64_t start;
        uint64_t end;

        bool operator<(const Interval& other) const { return start < other.start; }
    };
    std::vector<Interval> intervals;

    // Collect all extents in the partition table.
    for (const auto& partition : partitions_) {
        for (const auto& extent : partition->extents()) {
            LinearExtent* linear = extent->AsLinearExtent();
            if (!linear) {
                continue;
            }
            intervals.push_back(Interval{linear->physical_sector(),
                                         linear->physical_sector() + extent->num_sectors()});
        }
    }

    // Sort extents by starting sector.
    std::sort(intervals.begin(), intervals.end());

    // Find gaps that we can use for new extents. Note we store new extents in a
    // temporary vector, and only commit them if we are guaranteed enough free
    // space.
    std::vector<std::unique_ptr<LinearExtent>> new_extents;
    for (size_t i = 1; i < intervals.size(); i++) {
        const Interval& previous = intervals[i - 1];
        const Interval& current = intervals[i];

        if (previous.end >= current.start) {
            // There is no gap between these two extents, try the next one. Note that
            // extents may never overlap, but just for safety, we ignore them if they
            // do.
            assert(previous.end == current.start);
            continue;
        }

        // This gap is enough to hold the remainder of the space requested, so we
        // can allocate what we need and return.
        if (current.start - previous.end >= sectors_needed) {
            auto extent = std::make_unique<LinearExtent>(sectors_needed, previous.end);
            sectors_needed -= extent->num_sectors();
            new_extents.push_back(std::move(extent));
            break;
        }

        // This gap is not big enough to fit the remainder of the space requested,
        // so consume the whole thing and keep looking for more.
        auto extent = std::make_unique<LinearExtent>(current.start - previous.end, previous.end);
        sectors_needed -= extent->num_sectors();
        new_extents.push_back(std::move(extent));
    }

    // If we still have more to allocate, take it from the remaining free space
    // in the allocatable region.
    if (sectors_needed) {
        uint64_t first_sector;
        if (intervals.empty()) {
            first_sector = header_.first_logical_sector;
        } else {
            first_sector = intervals.back().end;
        }
        assert(first_sector <= header_.last_logical_sector);

        // Note: the last usable sector is inclusive.
        if (first_sector + sectors_needed > header_.last_logical_sector) {
            LERROR << "Not enough free space to expand partition: " << partition.name();
            return false;
        }
        auto extent = std::make_unique<LinearExtent>(sectors_needed, first_sector);
        new_extents.push_back(std::move(extent));
    }

    for (auto& extent : new_extents) {
        partition.AddExtent(std::move(extent));
    }
    return true;
}

void MetadataBuilder::ShrinkPartition(Partition& partition, uint64_t requested_size) {
    partition.ShrinkTo(requested_size);
}

std::unique_ptr<LpMetadata> MetadataBuilder::Export() {
    metadata_ = std::make_unique<LpMetadata>();
    metadata_->header = header_;

    // Flatten the partition and extent structures into an LpMetadata, which
    // makes it very easy to validate, serialize, or pass on to device-mapper.
    for (const auto& partition : partitions_) {
        LpMetadataPartition part;
        memset(&part, 0, sizeof(part));

        if (partition->name().size() > sizeof(part.name)) {
            fprintf(stderr, "partition name is too long: %s\n", partition->name().c_str());
            return nullptr;
        }
        if (partition->attributes() & ~(LP_PARTITION_ATTRIBUTE_MASK)) {
            fprintf(stderr, "partition %s has unsupported attribute\n", partition->name().c_str());
            return nullptr;
        }

        strncpy(part.name, partition->name().c_str(), sizeof(part.name));
        memcpy(part.guid, partition->guid(), sizeof(part.guid));

        part.first_extent_index = (uint32_t)metadata_->extents.size();
        part.num_extents = (uint32_t)partition->extents().size();
        part.attributes = partition->attributes();

        for (const auto& extent : partition->extents()) {
            extent->AddTo(metadata_.get());
        }
        metadata_->partitions.push_back(part);
    }

    metadata_->header.partitions.num_entries = (uint32_t)metadata_->partitions.size();
    metadata_->header.extents.num_entries = (uint32_t)metadata_->extents.size();
    return std::move(metadata_);
}

}  // namespace fs_mgr
}  // namespace android
