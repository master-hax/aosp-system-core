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

#include <libsnapshot/snapshot.h>

#include <dirent.h>
#include <math.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>
#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <fstab/fstab.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;
using android::dm::DeviceMapper;
using android::dm::DmDeviceState;
using android::dm::DmTable;
using android::dm::DmTargetLinear;
using android::dm::DmTargetSnapshot;
using android::dm::kSectorSize;
using android::dm::SnapshotStorageMode;
using android::fiemap::IImageManager;
using namespace std::chrono_literals;
using namespace std::string_literals;

// Unit is sectors, this is a 4K chunk.
static constexpr uint32_t kSnapshotChunkSize = 8;

class DeviceInfo final : public SnapshotManager::IDeviceInfo {
  public:
    std::string GetGsidDir() const override { return "ota"s; }
    std::string GetMetadataDir() const override { return "/metadata/ota/test"s; }
    bool IsRunningSnapshot() const override;
};

bool DeviceInfo::IsRunningSnapshot() const {
    // :TODO: implement this check.
    return true;
}

// Note: IIMageManager is an incomplete type in the header, so the default
// destructor doesn't work.
SnapshotManager::~SnapshotManager() {}

std::unique_ptr<SnapshotManager> SnapshotManager::New(IDeviceInfo* info) {
    if (!info) {
        info = new DeviceInfo();
    }
    return std::unique_ptr<SnapshotManager>(new SnapshotManager(info));
}

SnapshotManager::SnapshotManager(IDeviceInfo* device) : device_(device) {
    gsid_dir_ = device_->GetGsidDir();
    metadata_dir_ = device_->GetMetadataDir();
}

static std::string GetBaseName(const std::string& partition_name) {
    return partition_name + "-base";
}

static std::string GetCowName(const std::string& snapshot_name) {
    return snapshot_name + "-cow";
}

bool SnapshotManager::BeginUpdate() {
    auto file = LockExclusive();
    if (!file) return false;

    auto state = ReadUpdateState(file.get());
    if (state != UpdateState::None) {
        LOG(ERROR) << "An update is already in progress, cannot begin a new update";
        return false;
    }
    return WriteUpdateState(file.get(), UpdateState::Initiated);
}

bool SnapshotManager::CancelUpdate() {
    auto file = LockExclusive();
    if (!file) return false;

    UpdateState state = ReadUpdateState(file.get());
    if (state == UpdateState::None) return true;
    if (state != UpdateState::Initiated) {
        LOG(ERROR) << "Cannot cancel update after it has completed or started merging";
        return false;
    }

    if (!RemoveAllSnapshots(file.get())) {
        LOG(ERROR) << "Could not remove all snapshots";
        return false;
    }

    if (!WriteUpdateState(file.get(), UpdateState::None)) {
        LOG(ERROR) << "Could not write new update state";
        return false;
    }
    return true;
}

bool SnapshotManager::CreateSnapshot(LockedFile* lock, const std::string& name,
                                     uint64_t device_size, uint64_t snapshot_size,
                                     uint64_t cow_size) {
    CHECK(lock);
    if (!EnsureImageManager()) return false;

    // Sanity check these sizes. Like liblp, we guarantee the partition size
    // is respected, which means it has to be sector-aligned. (This guarantee
    // is useful for locating avb footers correctly). The COW size, however,
    // can be arbitrarily larger than specified, so we can safely round it up.
    if (device_size % kSectorSize != 0) {
        LOG(ERROR) << "Snapshot " << name
                   << " device size is not a multiple of the sector size: " << device_size;
        return false;
    }
    if (snapshot_size % kSectorSize != 0) {
        LOG(ERROR) << "Snapshot " << name
                   << " snapshot size is not a multiple of the sector size: " << snapshot_size;
        return false;
    }

    // Round the COW size up to the nearest sector.
    cow_size += kSectorSize - 1;
    cow_size &= ~(kSectorSize - 1);

    LOG(INFO) << "Snapshot " << name << " will have COW size " << cow_size;

    auto status_file = OpenSnapshotStatusFile(name, O_RDWR | O_CREAT, LOCK_EX);
    if (!status_file) return false;

    // Note, we leave the status file hanging around if we fail to create the
    // actual backing image. This is harmless, since it'll get removed when
    // CancelUpdate is called.
    SnapshotStatus status = {
            .state = "created",
            .device_size = device_size,
            .snapshot_size = snapshot_size,
    };
    if (!WriteSnapshotStatus(status_file.get(), status)) {
        PLOG(ERROR) << "Could not write snapshot status: " << name;
        return false;
    }

    auto cow_name = GetCowName(name);
    int cow_flags = IImageManager::CREATE_IMAGE_ZERO_FILL;
    return images_->CreateBackingImage(cow_name, cow_size, cow_flags);
}

bool SnapshotManager::MapSnapshot(LockedFile* lock, const std::string& name,
                                  const std::string& base_device,
                                  const std::chrono::milliseconds& timeout_ms,
                                  std::string* dev_path) {
    CHECK(lock);
    if (!EnsureImageManager()) return false;

    auto status_file = OpenSnapshotStatusFile(name, O_RDWR, LOCK_EX);
    if (!status_file) return false;

    SnapshotStatus status;
    if (!ReadSnapshotStatus(status_file.get(), &status)) {
        return false;
    }

    // Validate the block device size, as well as the requested snapshot size.
    // During this we also compute the linear sector region if any.
    {
        unique_fd fd(open(base_device.c_str(), O_RDONLY | O_CLOEXEC));
        if (fd < 0) {
            PLOG(ERROR) << "open failed: " << base_device;
            return false;
        }
        auto dev_size = get_block_device_size(fd);
        if (!dev_size) {
            PLOG(ERROR) << "Could not determine block device size: " << base_device;
            return false;
        }
        if (status.device_size != dev_size) {
            LOG(ERROR) << "Block device size for " << base_device << " does not match"
                       << "(expected " << status.device_size << ", got " << dev_size << ")";
            return false;
        }
    }
    if (status.device_size % kSectorSize != 0) {
        LOG(ERROR) << "invalid blockdev size for " << base_device << ": " << status.device_size;
        return false;
    }
    if (status.snapshot_size % kSectorSize != 0 || status.snapshot_size > status.device_size) {
        LOG(ERROR) << "Invalid snapshot size for " << base_device << ": " << status.snapshot_size;
        return false;
    }
    uint64_t snapshot_sectors = status.snapshot_size / kSectorSize;
    uint64_t linear_sectors = (status.device_size - status.snapshot_size) / kSectorSize;

    auto cow_name = GetCowName(name);

    std::string cow_dev;
    if (!images_->MapImageDevice(cow_name, timeout_ms, &cow_dev)) {
        return false;
    }

    auto& dm = DeviceMapper::Instance();

    // Merging is a global state, not per-snapshot. We do however track the
    // progress of individual snapshots' merges.
    SnapshotStorageMode mode;
    UpdateState update_state = ReadUpdateState(lock);
    if (update_state == UpdateState::Merging || update_state == UpdateState::MergeCompleted) {
        mode = SnapshotStorageMode::Merge;
    } else {
        mode = SnapshotStorageMode::Persistent;
    }

    // The kernel (tested on 4.19) crashes horribly if a device has both a snapshot
    // and a linear target in the same table. Instead, we stack them, and give the
    // snapshot device a different name. It is not exposed to the caller in this
    // case.
    auto snap_name = (linear_sectors > 0) ? name + "-inner" : name;

    DmTable table;
    table.Emplace<DmTargetSnapshot>(0, snapshot_sectors, base_device, cow_dev, mode,
                                    kSnapshotChunkSize);
    if (!dm.CreateDevice(snap_name, table, dev_path, timeout_ms)) {
        LOG(ERROR) << "Could not create snapshot device: " << snap_name;
        images_->UnmapImageDevice(cow_name);
        return false;
    }

    if (linear_sectors) {
        // Our stacking will looks like this:
        //     [linear, linear] ; to snapshot, and non-snapshot region of base device
        //     [snapshot-inner]
        //     [base device]   [cow]
        DmTable table;
        table.Emplace<DmTargetLinear>(0, snapshot_sectors, *dev_path, 0);
        table.Emplace<DmTargetLinear>(snapshot_sectors, linear_sectors, base_device,
                                      snapshot_sectors);
        if (!dm.CreateDevice(name, table, dev_path, timeout_ms)) {
            LOG(ERROR) << "Could not create outer snapshot device: " << name;
            dm.DeleteDevice(snap_name);
            images_->UnmapImageDevice(cow_name);
            return false;
        }
    }

    // :TODO: when merging is implemented, we need to add an argument to the
    // status indicating how much progress is left to merge. (device-mapper
    // does not retain the initial values, so we can't derive them.)
    return true;
}

bool SnapshotManager::UnmapSnapshot(LockedFile* lock, const std::string& name) {
    CHECK(lock);
    if (!EnsureImageManager()) return false;

    auto status_file = OpenSnapshotStatusFile(name, O_RDWR, LOCK_EX);
    if (!status_file) return false;

    SnapshotStatus status;
    if (!ReadSnapshotStatus(status_file.get(), &status)) {
        return false;
    }

    auto& dm = DeviceMapper::Instance();
    if (dm.GetState(name) != DmDeviceState::INVALID && !dm.DeleteDevice(name)) {
        LOG(ERROR) << "Could not delete snapshot device: " << name;
        return false;
    }

    // There may be an extra device, since the kernel doesn't let us have a
    // snapshot and linear target in the same table.
    auto dm_name = GetSnapshotDeviceName(name, status);
    if (name != dm_name && !dm.DeleteDevice(dm_name)) {
        LOG(ERROR) << "Could not delete inner snapshot device: " << dm_name;
        return false;
    }

    auto cow_name = GetCowName(name);
    if (images_->IsImageMapped(cow_name) && !images_->UnmapImageDevice(cow_name)) {
        return false;
    }
    return true;
}

bool SnapshotManager::DeleteSnapshot(LockedFile* lock, const std::string& name) {
    CHECK(lock);
    if (!EnsureImageManager()) return false;

    if (!UnmapSnapshot(lock, name)) {
        LOG(ERROR) << "Snapshot could not be unmapped for deletion: " << name;
        return false;
    }

    // Take the snapshot's lock after Unmap, since it will also try to lock.
    auto status_file = OpenSnapshotStatusFile(name, O_RDONLY, LOCK_EX);
    if (!status_file) return false;

    auto cow_name = GetCowName(name);
    if (!images_->BackingImageExists(cow_name)) {
        return true;
    }
    if (!images_->DeleteBackingImage(cow_name)) {
        return false;
    }

    if (!android::base::RemoveFileIfExists(status_file->path())) {
        LOG(ERROR) << "Failed to remove status file: " << status_file->path();
        return false;
    }
    return true;
}

bool SnapshotManager::InitiateMerge() {
    return false;
}

bool SnapshotManager::WaitForMerge() {
    return false;
}

bool SnapshotManager::RemoveAllSnapshots(LockedFile* lock) {
    std::vector<std::string> snapshots;
    if (!ListSnapshots(lock, &snapshots)) {
        LOG(ERROR) << "Could not list snapshots";
        return false;
    }

    bool ok = true;
    for (const auto& name : snapshots) {
        ok &= DeleteSnapshot(lock, name);
    }
    return ok;
}

UpdateState SnapshotManager::GetUpdateState(double* progress) {
    auto file = LockShared();
    if (!file) {
        return UpdateState::None;
    }

    auto state = ReadUpdateState(file.get());
    if (progress) {
        *progress = 0.0;
        if (state == UpdateState::Merging) {
            // :TODO: When merging is implemented, set progress_val.
        } else if (state == UpdateState::MergeCompleted) {
            *progress = 100.0;
        }
    }
    return state;
}

bool SnapshotManager::ListSnapshots(LockedFile* lock, std::vector<std::string>* snapshots) {
    CHECK(lock);

    auto dir_path = metadata_dir_ + "/snapshots"s;
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(dir_path.c_str()), closedir);
    if (!dir) {
        PLOG(ERROR) << "opendir failed: " << dir_path;
        return false;
    }

    struct dirent* dp;
    while ((dp = readdir(dir.get())) != nullptr) {
        if (dp->d_type != DT_REG) continue;
        snapshots->emplace_back(dp->d_name);
    }
    return true;
}

auto SnapshotManager::OpenFile(const std::string& file, int open_flags, int lock_flags)
        -> std::unique_ptr<LockedFile> {
    unique_fd fd(open(file.c_str(), open_flags | O_CLOEXEC | O_NOFOLLOW | O_SYNC, 0660));
    if (fd < 0) {
        PLOG(ERROR) << "Open failed: " << file;
        return nullptr;
    }
    if (flock(fd, lock_flags) < 0) {
        PLOG(ERROR) << "Acquire flock failed: " << file;
        return nullptr;
    }
    return std::make_unique<LockedFile>(file, std::move(fd));
}

SnapshotManager::LockedFile::~LockedFile() {
    if (flock(fd_, LOCK_UN) < 0) {
        PLOG(ERROR) << "Failed to unlock file: " << path_;
    }
}

std::unique_ptr<SnapshotManager::LockedFile> SnapshotManager::OpenStateFile(int open_flags,
                                                                            int lock_flags) {
    auto state_file = metadata_dir_ + "/state"s;
    return OpenFile(state_file, open_flags, lock_flags);
}

std::unique_ptr<SnapshotManager::LockedFile> SnapshotManager::LockShared() {
    return OpenStateFile(O_RDONLY, LOCK_SH);
}

std::unique_ptr<SnapshotManager::LockedFile> SnapshotManager::LockExclusive() {
    return OpenStateFile(O_RDWR | O_CREAT, LOCK_EX);
}

UpdateState SnapshotManager::ReadUpdateState(LockedFile* file) {
    // Reset position since some calls read+write.
    if (lseek(file->fd(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek state file failed";
        return UpdateState::None;
    }

    std::string contents;
    if (!android::base::ReadFdToString(file->fd(), &contents)) {
        PLOG(ERROR) << "Read state file failed";
        return UpdateState::None;
    }

    if (contents.empty() || contents == "none") {
        return UpdateState::None;
    } else if (contents == "initiated") {
        return UpdateState::Initiated;
    } else if (contents == "unverified") {
        return UpdateState::Unverified;
    } else if (contents == "merging") {
        return UpdateState::Merging;
    } else if (contents == "merge-completed") {
        return UpdateState::MergeCompleted;
    } else {
        LOG(ERROR) << "Unknown merge state in update state file";
        return UpdateState::None;
    }
}

bool SnapshotManager::WriteUpdateState(LockedFile* file, UpdateState state) {
    std::string contents;
    switch (state) {
        case UpdateState::None:
            contents = "none";
            break;
        case UpdateState::Initiated:
            contents = "initiated";
            break;
        case UpdateState::Unverified:
            contents = "unverified";
            break;
        case UpdateState::Merging:
            contents = "merging";
            break;
        case UpdateState::MergeCompleted:
            contents = "merge-completed";
            break;
        default:
            LOG(ERROR) << "Unknown update state";
            return false;
    }

    if (!Truncate(file)) return false;
    if (!android::base::WriteStringToFd(contents, file->fd())) {
        PLOG(ERROR) << "Could not write to state file";
        return false;
    }
    return true;
}

auto SnapshotManager::OpenSnapshotStatusFile(const std::string& name, int open_flags,
                                             int lock_flags) -> std::unique_ptr<LockedFile> {
    auto file = metadata_dir_ + "/snapshots/"s + name;
    return OpenFile(file, open_flags, lock_flags);
}

bool SnapshotManager::ReadSnapshotStatus(LockedFile* file, SnapshotStatus* status) {
    // Reset position since some calls read+write.
    if (lseek(file->fd(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek status file failed";
        return false;
    }

    std::string contents;
    if (!android::base::ReadFdToString(file->fd(), &contents)) {
        PLOG(ERROR) << "read status file failed";
        return false;
    }
    auto pieces = android::base::Split(contents, " ");
    if (pieces.size() != 5) {
        LOG(ERROR) << "Invalid status line for snapshot: " << file->path();
        return false;
    }

    status->state = pieces[0];
    if (!android::base::ParseUint(pieces[1], &status->device_size)) {
        LOG(ERROR) << "Invalid device size in status line for: " << file->path();
        return false;
    }
    if (!android::base::ParseUint(pieces[2], &status->snapshot_size)) {
        LOG(ERROR) << "Invalid snapshot size in status line for: " << file->path();
        return false;
    }
    if (!android::base::ParseUint(pieces[3], &status->sectors_allocated)) {
        LOG(ERROR) << "Invalid snapshot size in status line for: " << file->path();
        return false;
    }
    if (!android::base::ParseUint(pieces[4], &status->metadata_sectors)) {
        LOG(ERROR) << "Invalid snapshot size in status line for: " << file->path();
        return false;
    }
    return true;
}

bool SnapshotManager::WriteSnapshotStatus(LockedFile* file, const SnapshotStatus& status) {
    std::vector<std::string> pieces = {
            status.state,
            std::to_string(status.device_size),
            std::to_string(status.snapshot_size),
            std::to_string(status.sectors_allocated),
            std::to_string(status.metadata_sectors),
    };
    auto contents = android::base::Join(pieces, " ");

    if (!Truncate(file)) return false;
    if (!android::base::WriteStringToFd(contents, file->fd())) {
        PLOG(ERROR) << "write to status file failed: " << file->path();
        return false;
    }
    return true;
}

bool SnapshotManager::Truncate(LockedFile* file) {
    if (lseek(file->fd(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek file failed: " << file->path();
        return false;
    }
    if (ftruncate(file->fd(), 0) < 0) {
        PLOG(ERROR) << "truncate failed: " << file->path();
        return false;
    }
    return true;
}

std::string SnapshotManager::GetSnapshotDeviceName(const std::string& snapshot_name,
                                                   const SnapshotStatus& status) {
    if (status.device_size != status.snapshot_size) {
        return snapshot_name + "-inner";
    }
    return snapshot_name;
}

bool SnapshotManager::EnsureImageManager() {
    if (images_) return true;

    // For now, use a preset timeout.
    images_ = android::fiemap::IImageManager::Open(gsid_dir_, 15000ms);
    if (!images_) {
        LOG(ERROR) << "Could not open ImageManager";
        return false;
    }
    return true;
}

enum class LoopDirective { BREAK, CONTINUE };

// Execute |func| on each partition in |builder| that ends with |suffix|.
// If |func| return CONTINUE, continue the loop. Otherwise, exit the loop
// and return false.
static bool ForEachPartition(
        fs_mgr::MetadataBuilder* builder,
        const std::string& suffix,
        const std::function<LoopDirective(fs_mgr::Partition*)>& func) {
    for (const auto& group : builder->ListGroups()) {
        for (auto* partition : builder->ListPartitionsInGroup(group)) {
            if (!base::EndsWith(partition->name(), suffix)) {
                continue;
            }
            if (func(partition) == LoopDirective::BREAK) return false;
        }
    }
    return true;
}

// Helper class that creates COW for a partition.
struct PartitionCowCreator {
    // The metadata that will be written to target metadata slot.
    fs_mgr::MetadataBuilder* target_metadata;
    // The suffix of the target slot.
    std::string target_suffix;
    // The partition in target_metadata that needs to be snapshotted.
    fs_mgr::Partition* target_partition;
    // The metadata at the current slot (that would be used if the device boots
    // normally). This is used to determine which extents are being used.
    fs_mgr::MetadataBuilder* current_metadata;
    // The suffix of the current slot.
    std::string current_suffix;
    // The COW size given by client code.
    std::optional<uint64_t> cow_size;

    // Round |d| up to a multiple of |block_size|.
    static uint64_t RoundUp(double d, uint64_t block_size) {
        uint64_t ret = ((uint64_t)ceil(d) + block_size - 1) / block_size * block_size;
        CHECK(ret >= d) << "Can't round " << d << " up to a multiple of " << block_size;
        return ret;
    }

    // Intersect |target_extent| from target_metadata with |existing_extent| from
    // |existing_metadata|. The result uses block device indices from
    // |target_metadata|. If no intersection, return an extent with num_sectors() ==
    // 0.
    static std::unique_ptr<fs_mgr::Extent> Intersect(
        fs_mgr::Extent* target_extent,
        fs_mgr::MetadataBuilder* target_metadata,
        fs_mgr::Extent* existing_extent,
        fs_mgr::MetadataBuilder* existing_metadata) {

        // Convert target_extent and existing_extent to linear extents. Zero extents
        // doesn't matter and doesn't result in any intersection.
        auto existing_linear_extent = existing_extent->AsLinearExtent();
        if (!existing_extent) return std::make_unique<fs_mgr::ZeroExtent>(0);

        auto target_linear_extent = target_extent->AsLinearExtent();
        if (!target_linear_extent) return std::make_unique<fs_mgr::ZeroExtent>(0);

        // Compare block device by names. Technically, block devices can have
        // different indices in metadata in different slots. In reality:
        // (1) For retrofit DAP devices, dynamic partitions of different slots
        //     occupy different block devices (e.g. logical system_a can only use
        //     physical system_a, vendor_a, etc.)
        // (2) For launch DAP devices, there are only one super block device and
        //     the two names from the two slots should always match.
        auto existing_block_device = existing_metadata->GetBlockDevicePartitionName(
            existing_linear_extent->device_index());
        auto target_block_device = target_metadata->GetBlockDevicePartitionName(
            target_linear_extent->device_index());
        if (existing_block_device != target_block_device)
            return std::make_unique<fs_mgr::ZeroExtent>(0);

        // Compute the begin and end sector numbers of the potential intersection.
        uint64_t begin = std::max(existing_linear_extent->physical_sector(),
                                  target_linear_extent->physical_sector());
        uint64_t end = std::min(existing_linear_extent->end_sector(),
                                target_linear_extent->end_sector());

        if (end <= begin) return std::make_unique<fs_mgr::ZeroExtent>(0);

        return std::make_unique<fs_mgr::LinearExtent>(
            end - begin, target_linear_extent->device_index(), begin);
    }

    // Intersect |target_extent| from this->target_metadata with |existing_extent| from
    // this->current_metadata. The result uses block device indices from
    // |target_metadata|. If no intersection, return an extent with num_sectors() ==
    // 0.
    std::unique_ptr<fs_mgr::Extent> Intersect(
        fs_mgr::Extent* target_extent,
        fs_mgr::Extent* existing_extent) {

        return Intersect(target_extent, target_metadata, existing_extent, current_metadata);
    }

    // Check that partition |p| contains |e| fully. Both of them should
    // be from |target_metadata|.
    // Returns true as long as |e| is a subrange of any extent of |p|.
    bool HasExtent(fs_mgr::Partition* p, fs_mgr::Extent* e) {
        for (auto& partition_extent : p->extents()) {
            auto intersection = Intersect(
                partition_extent.get(), target_metadata, e, target_metadata);
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
    std::optional<uint64_t> GetSnapshotSize() {
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

        // Sanity check that all recorded intersections are indeed within target_partition[0..snapshot_sectors].
        fs_mgr::Partition target_partition_snapshot = target_partition->GetBeginningExtents(snapshot_size);
        for (const auto& intersection : intersections) {
            if (!HasExtent(&target_partition_snapshot, intersection.get())) {
                auto linear_intersection = intersection->AsLinearExtent();
                LOG(ERROR) << "Extent "
                    << (linear_intersection ? (
                        std::to_string(linear_intersection->physical_sector()) + "," +
                        std::to_string(linear_intersection->end_sector())) : "") <<
                        " is not part of Partition " << target_partition->name()
                    << "[0.." << snapshot_size
                    << "]. The metadata wasn't constructed correctly. This should not happen.";
                return std::nullopt;
            }
        }

        return snapshot_size;
    }

    struct Return {
        uint64_t device_size = 0;
        uint64_t snapshot_size = 0;
        uint64_t cow_partition_size = 0;
        uint64_t cow_file_size = 0;
    };

    std::optional<Return> operator()() {
        static constexpr double kCowEstimateFactor = 1.1;

        Return ret;
        ret.device_size = target_partition->size();

        auto snapshot_size = GetSnapshotSize();
        if (!snapshot_size.has_value()) return std::nullopt;

        ret.snapshot_size = *snapshot_size;

        // TODO: always read from cow_size when the COW size is written in
        // update package. kCowEstimateFactor is good for prototyping but
        // we can't use that in production.
        if (!cow_size.has_value()) {
            cow_size = RoundUp(ret.snapshot_size * kCowEstimateFactor, fs_mgr::kDefaultBlockSize);
        }

        // TODO: create COW partition in target_metadata to save space.
        ret.cow_partition_size = 0;
        ret.cow_file_size = (*cow_size) - ret.cow_partition_size;

        return ret;
    }

};

bool SnapshotManager::CreateCowForUpdate(
    fs_mgr::MetadataBuilder* target_metadata,
    const std::string& target_suffix,
    fs_mgr::MetadataBuilder* current_metadata,
    const std::string& current_suffix,
    const std::map<std::string, uint64_t>& cow_sizes) {

    auto lock = OpenStateFile(O_RDWR, LOCK_EX);

    // Add _{target_suffix} to COW size map.
    std::map<std::string, uint64_t> suffixed_cow_sizes;
    for (const auto& [name, size] : cow_sizes) {
        suffixed_cow_sizes[name + target_suffix] = size;
    }

    bool res = ForEachPartition(target_metadata, target_suffix, [&] (auto* target_partition) {
        std::optional<uint64_t> cow_size = std::nullopt;
        auto it = suffixed_cow_sizes.find(target_partition->name());
        if (it != suffixed_cow_sizes.end()) cow_size = it->second;

        auto snapshot_params = PartitionCowCreator{
            target_metadata, target_suffix, target_partition,
            current_metadata, current_suffix, cow_size}();
        if (!snapshot_params.has_value()) {
            return LoopDirective::BREAK;
        }

        if (!CreateSnapshot(lock.get(), target_partition->name(),
                            snapshot_params->device_size,
                            snapshot_params->snapshot_size,
                            snapshot_params->cow_file_size)) {
            return LoopDirective::BREAK;
        }
        return LoopDirective::CONTINUE;
    });

    return res;
}

bool SnapshotManager::MapSnapshotDevicesForUpdate(
    const std::string& super_device,
    fs_mgr::MetadataBuilder* target_metadata,
    const std::string& target_suffix,
    const std::chrono::milliseconds& timeout_ms_per_device) {

    auto lock = OpenStateFile(O_RDWR, LOCK_EX);

    auto exported = target_metadata->Export();
    if (!exported) return false;

    bool map_success = true;
    ForEachPartition(target_metadata, target_suffix, [&](auto* target_partition) {
        std::string partition_name = target_partition->name();
        std::string base_name = GetBaseName(partition_name);
        if (target_partition->extents().empty()) {
            LOG(INFO) << "Skipping zero-length logical partition: " << base_name;
            return LoopDirective::CONTINUE;
        }

        std::string base_path;
        if (!fs_mgr::CreateLogicalPartition(super_device, *exported, partition_name,
                                            base_name,
                                            true /* force_writable */,
                                            timeout_ms_per_device, &base_path)) {
            LOG(ERROR) << "Could not create logical partition: " << base_name;
            map_success = false;
            return LoopDirective::CONTINUE; // Attempt to map others
        }

        std::string snapshot_path;
        if (!MapSnapshot(lock.get(),
                         partition_name,
                         base_path, timeout_ms_per_device, &snapshot_path)) {
            LOG(ERROR) << "Could not map snapshot: " << partition_name;
            map_success = false;
            return LoopDirective::CONTINUE; // Attempt to map others
        }

        LOG(INFO) << "Mapped " << partition_name << " as snapshot device at "
                  << snapshot_path;
        return LoopDirective::CONTINUE;
    });

    return map_success;
}

bool SnapshotManager::UnmapSnapshotDevice(const std::string& target_partition_name) {
    auto lock = OpenStateFile(O_RDWR, LOCK_EX);
    return UnmapSnapshot(lock.get(), target_partition_name);
}

}  // namespace snapshot
}  // namespace android
