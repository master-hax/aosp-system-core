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
#include <sys/file.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>
#include <libdm/dm.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;
using android::dm::DeviceMapper;
using android::dm::DmDeviceState;
using android::dm::DmTable;
using android::dm::DmTargetLinear;
using android::dm::DmTargetSnapshot;
using android::dm::SnapshotStorageMode;
using android::fiemap::IImageManager;
using namespace std::string_literals;

class DeviceInfo final : public SnapshotManager::IDeviceInfo {
  public:
    std::string GetGsidDir() const override { return "ota"s; }
    std::string GetMetadataDir() const override { return "/metadata/ota/test"s; }
};

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

static std::string GetCowName(const std::string& snapshot_name) {
    return snapshot_name + "-cow";
}

bool SnapshotManager::BeginUpdate() {
    auto file = OpenStateFile(O_RDWR | O_CREAT, LOCK_EX);
    if (!file) {
        LOG(ERROR) << "Could not open or create update state file";
        return false;
    }

    auto state = ReadUpdateState(file.get());
    if (state != UpdateState::None) {
        LOG(ERROR) << "An update is already in progress, cannot begin a new update";
        return false;
    }
    return WriteUpdateState(file.get(), UpdateState::Initiated);
}

bool SnapshotManager::CancelUpdate() {
    auto file = OpenStateFile(O_RDWR | O_CREAT, LOCK_EX);
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
    return images_->createBackingImage(cow_name, cow_size, cow_flags).isOk();
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
    static const uint64_t kSectorSize = 512;
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

    android::fiemap::MappedImage mapping;
    auto cow_name = GetCowName(name);
    if (!images_->mapImageDevice(cow_name, timeout_ms.count(), &mapping).isOk()) {
        return false;
    }

    // Unit is sectors, this is a 4K chunk.
    static constexpr uint32_t kChunkSize = 8;
    auto& dm = DeviceMapper::Instance();
    auto mode = (status.state == "merging") ? SnapshotStorageMode::Merge
                                            : SnapshotStorageMode::Persistent;

    // The kernel (tested on 4.19) crashes horribly if a device has both a snapshot
    // and a linear target in the same table. Instead, we stack them, and give the
    // snapshot device a different name. It is not exposed to the caller in this
    // case.
    auto snap_name = (linear_sectors > 0) ? name + "-inner" : name;

    DmTable table;
    table.Emplace<DmTargetSnapshot>(0, snapshot_sectors, base_device, mapping.path, mode,
                                    kChunkSize);
    if (!dm.CreateDevice(snap_name, table, dev_path, timeout_ms)) {
        LOG(ERROR) << "Could not create snapshot device: " << snap_name;
        images_->unmapImageDevice(cow_name);
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
            images_->unmapImageDevice(cow_name);
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
    if (dm.GetState(name) == DmDeviceState::INVALID) {
        return true;
    }
    if (!dm.DeleteDevice(name)) {
        LOG(ERROR) << "Could not delete snapshot device: " << name;
        return false;
    }
    if (status.device_size > status.snapshot_size) {
        // There is an extra device, since the kernel doesn't let us have a
        // snapshot and linear target in the same table.
        if (!dm.DeleteDevice(name + "-inner")) {
            LOG(ERROR) << "Could not delete inner snapshot device: " << name;
            return false;
        }
    }

    auto cow_name = GetCowName(name);
    return images_->unmapImageDevice(cow_name).isOk();
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
    bool image_exists = false;
    if (!images_->backingImageExists(cow_name, &image_exists).isOk() || !image_exists) {
        return true;
    }
    if (!images_->deleteBackingImage(cow_name).isOk()) {
        return false;
    }

    std::string error;
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
    auto file = OpenStateFile(O_RDONLY, LOCK_SH);
    if (!file) {
        return UpdateState::None;
    }

    auto state = ReadUpdateState(file.get());
    double progress_val = 0.0;
    if (state == UpdateState::Merging) {
        // :TODO: When merging is implemented, set progress_val.
    } else if (state == UpdateState::MergeCompleted) {
        progress_val = 100.0;
    }

    if (progress) *progress = progress_val;
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

auto SnapshotManager::OpenStateFile(int open_flags, int lock_flags) -> std::unique_ptr<LockedFile> {
    auto state_file = metadata_dir_ + "/state"s;
    return OpenFile(state_file, open_flags, lock_flags);
}

UpdateState SnapshotManager::ReadUpdateState(LockedFile* file) {
    // Reset position since some calls read+write.
    if (lseek(file->fd(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek state file failed";
        return {};
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
        return {};
    }

    std::string contents;
    if (!android::base::ReadFdToString(file->fd(), &contents)) {
        PLOG(ERROR) << "read status file failed";
        return {};
    }
    auto pieces = android::base::Split(contents, " ");
    if (pieces.size() != 3) {
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
    return true;
}

bool SnapshotManager::WriteSnapshotStatus(LockedFile* file, const SnapshotStatus& status) {
    std::vector<std::string> pieces = {
            status.state,
            std::to_string(status.device_size),
            std::to_string(status.snapshot_size),
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

bool SnapshotManager::EnsureImageManager() {
    if (images_ != nullptr) {
        return true;
    }

    images_ = android::fiemap::ImageManager::Open(gsid_dir_);
    if (!images_) {
        LOG(ERROR) << "Could not open ImageManagerBridge";
        return false;
    }
    return true;
}

}  // namespace snapshot
}  // namespace android
