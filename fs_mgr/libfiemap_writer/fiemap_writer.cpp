/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

#include <libfiemap_writer/fiemap_writer.h>

namespace android {
namespace fiemap_writer {

bool FiemapWriter::Create(const std::string& file_path, uint64_t file_size) {
    if (!file_path_.empty()) {
        // This object is already associated with a file. Return failure
        // if something tries to call Create() twice.
        return false;
    }

    ::android::base::unique_fd file_fd(TEMP_FAILURE_RETRY(
            open(file_path.c_str(), O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR)));
    if (file_fd < 0) {
        PLOG(ERROR) << "Failed to create file at: " << file_path;
        return false;
    }

    std::string abs_path;
    if (!::android::base::Realpath(file_path, &abs_path)) {
        PLOG(ERROR) << "Invalid file path: " << file_path;
        Cleanup(file_path);
        return false;
    }

    std::string bdev_path;
    if (!FileToBlockDevPath(abs_path, &bdev_path)) {
        LOG(ERROR) << "Failed to get block_dev path for file: " << file_path;
        Cleanup(abs_path);
        return false;
    }

    ::android::base::unique_fd bdev_fd(
            TEMP_FAILURE_RETRY(open(bdev_path.c_str(), O_RDWR | O_CLOEXEC)));
    if (bdev_fd < 0) {
        PLOG(ERROR) << "Failed to open block device: " << bdev_path;
        Cleanup(abs_path);
        return false;
    }

    if (!AllocateFileWithSize(file_fd, abs_path, bdev_fd, bdev_path, file_size)) {
        Cleanup(abs_path);
        return false;
    }

    if (!ReadFiemap(file_fd, abs_path)) {
        Cleanup(abs_path);
        return false;
    }

    file_path_ = abs_path;
    file_size_ = file_size;
    file_offset_ = 0;
    bdev_path_ = bdev_path;
    bdev_fd_ = std::move(bdev_fd);
    file_fd_ = std::move(file_fd);
    return true;
}

uint64_t FiemapWriter::BlockSize() const {
    return 0;
}

void FiemapWriter::Flush() const {}

const std::vector<struct fiemap_extent>& FiemapWriter::Fiemap() {
    return fiemap_;
}

bool FiemapWriter::Write(off64_t off, uint8_t* buffer, uint64_t size) {
    return false;
}

bool FiemapWriter::Append(uint8_t* buffer, uint64_t size) {
    return false;
}

bool FiemapWriter::Read(off64_t off, uint8_t* buffer, uint64_t size) {
    return false;
}

// private helpers
bool FiemapWriter::FileToBlockDevPath(const std::string& file_path, std::string* bdev_path) {
    struct stat sb;
    if (stat(file_path.c_str(), &sb)) {
        PLOG(ERROR) << "Failed to get stat for: " << file_path;
        return false;
    }

    std::string bdev_name;
    if (!BlockDevToName(major(sb.st_dev), minor(sb.st_dev), &bdev_name)) {
        LOG(ERROR) << "Failed to get block device name for " << major(sb.st_dev) << ":"
                   << minor(sb.st_dev);
        return false;
    }

    *bdev_path = ::android::base::StringPrintf("%s/%s", kBlockDevDir, bdev_name.c_str());
    return true;
}

bool FiemapWriter::BlockDevToName(uint32_t major, uint32_t minor, std::string* bdev_name) {
    // The symlinks in /sys/dev/block point to the block device node under /sys/device/..
    // The directory name in the target corresponds to the name of the block device. We use
    // that to extract the block device name.
    // e.g for block device name 'ram0', there exists a symlink named '1:0' in /sys/dev/block as
    // follows.
    //    1:0 -> ../../devices/virtual/block/ram0
    std::string sysfs_path = ::android::base::StringPrintf("%s/%u:%u", kSysDevBlock, major, minor);
    std::string sysfs_bdev;

    if (!::android::base::Readlink(sysfs_path, &sysfs_bdev)) {
        PLOG(ERROR) << "Failed to read link at: " << sysfs_path;
        return false;
    }

    *bdev_name = ::android::base::Basename(sysfs_bdev);
    // Paranoid sanity check to make sure we just didn't get the
    // input in return as-is.
    if (sysfs_bdev == *bdev_name) {
        LOG(ERROR) << "Malformed symlink for block device: " << sysfs_bdev;
        return false;
    }

    return true;
}

void FiemapWriter::Cleanup(const std::string& file_path) {
    // clear Fiemap, unlink file.
    fiemap_.clear();

    if (unlink(file_path.c_str())) {
        PLOG(ERROR) << "Failed to unlink file: " << file_path;
    }
}

bool FiemapWriter::PerformBlockDevChecks(int bdev_fd, const std::string& bdev_path,
                                         uint64_t file_size) {
    // Make sure we are talking to a block device first ..
    struct stat sb;
    if (stat(bdev_path.c_str(), &sb)) {
        PLOG(ERROR) << "Failed to get stat for block device: " << bdev_path;
        return false;
    }

    if ((sb.st_mode & S_IFMT) != S_IFBLK) {
        PLOG(ERROR) << "File: " << bdev_path << " is not a block device";
        return false;
    }

    // Check if the size aligned to the block size of the block device.
    // We need this to be true in order to be able to write the file using FIEMAP.
    // TODO: For some reason, the block device ioctl require the argument to be initialized
    // to zero even if its the out parameter for the given ioctl cmd.
    uint64_t blksz = 0;
    if (ioctl(bdev_fd, BLKBSZGET, &blksz)) {
        PLOG(ERROR) << "Failed to get block size for: " << bdev_path;
        return false;
    }

    if (file_size % blksz) {
        LOG(ERROR) << "File size " << file_size << " is not aligned to block size " << blksz
                   << " of " << bdev_path;
        return false;
    }

    block_size_ = blksz;
    return true;
}

bool FiemapWriter::PerformFsChecks(int file_fd, const std::string& file_path, uint64_t file_size) {
    struct statfs64 sfs;
    if (fstatfs64(file_fd, &sfs)) {
        PLOG(ERROR) << "Failed to read file system status at: " << file_path;
        return false;
    }

    // Check if the filesystem is of supported types.
    // Only ext4 and f2fs are tested and supported.
    if ((sfs.f_type != EXT4_SUPER_MAGIC) && (sfs.f_type != F2FS_SUPER_MAGIC)) {
        LOG(ERROR) << "Unsupported file system type: 0x" << std::hex << sfs.f_type;
        return false;
    }

    uint64_t available_bytes = sfs.f_bsize * sfs.f_bavail;
    if (available_bytes <= file_size) {
        LOG(ERROR) << "Not enough free space in file system to create file of size : " << file_size;
        return false;
    }

    // TODO: check if free space is equal or above given threshold
    fs_type_ = sfs.f_type;
    return true;
}

bool FiemapWriter::PinFile(int file_fd, const std::string& file_path) {
    if (fs_type_ == 0) {
        LOG(ERROR) << "Unknown file system type while pinning: " << file_path;
        return false;
    }

    if (fs_type_ == EXT4_SUPER_MAGIC) {
        // No pinning necessary for ext4. The blocks, once allocated, are expected
        // to be fixed.
        return true;
    }

    if (fs_type_ != F2FS_SUPER_MAGIC) {
        LOG(ERROR) << "Unsupported file system type: 0x" << std::hex << fs_type_;
        return false;
    }

// F2FS-specific ioctl
// It requires the below kernel commit merged in v4.16-rc1.
//   1ad71a27124c ("f2fs: add an ioctl to disable GC for specific file")
// In android-4.4,
//   56ee1e817908 ("f2fs: updates on v4.16-rc1")
// In android-4.9,
//   2f17e34672a8 ("f2fs: updates on v4.16-rc1")
// In android-4.14,
//   ce767d9a55bc ("f2fs: updates on v4.16-rc1")
#ifndef F2FS_IOC_SET_PIN_FILE
#ifndef F2FS_IOCTL_MAGIC
#define F2FS_IOCTL_MAGIC 0xf5
#endif
#define F2FS_IOC_SET_PIN_FILE _IOW(F2FS_IOCTL_MAGIC, 13, __u32)
#endif

    uint32_t pin_status = 1;
    if (ioctl(file_fd, F2FS_IOC_SET_PIN_FILE, &pin_status) < 0) {
        PLOG(ERROR) << "Failed to pin the file: " << file_path;
        return false;
    }

    return true;
}

bool FiemapWriter::PinFileStatus(int file_fd, const std::string& file_path) {
    if (fs_type_ == 0) {
        LOG(ERROR) << "Unknown file system type while pinning: " << file_path;
        return false;
    }

    if (fs_type_ == EXT4_SUPER_MAGIC) {
        // No pinning necessary for ext4. The blocks, once allocated, are expected
        // to be fixed.
        return true;
    }

    if (fs_type_ != F2FS_SUPER_MAGIC) {
        LOG(ERROR) << "Unsupported file system type: 0x" << std::hex << fs_type_;
        return false;
    }

// F2FS-specific ioctl
// It requires the below kernel commit merged in v4.16-rc1.
//   1ad71a27124c ("f2fs: add an ioctl to disable GC for specific file")
// In android-4.4,
//   56ee1e817908 ("f2fs: updates on v4.16-rc1")
// In android-4.9,
//   2f17e34672a8 ("f2fs: updates on v4.16-rc1")
// In android-4.14,
//   ce767d9a55bc ("f2fs: updates on v4.16-rc1")
#ifndef F2FS_IOC_GET_PIN_FILE
#ifndef F2FS_IOCTL_MAGIC
#define F2FS_IOCTL_MAGIC 0xf5
#endif
#define F2FS_IOC_GET_PIN_FILE _IOR(F2FS_IOCTL_MAGIC, 14, __u32)
#endif

    uint32_t pin_status;
    if (ioctl(file_fd, F2FS_IOC_GET_PIN_FILE, &pin_status) < 0) {
        PLOG(ERROR) << "Failed to pin the file: " << file_path;
        return false;
    }

    return !!pin_status;
}

void FiemapWriter::LogExtent(struct fiemap_extent* ext) {
    LOG(INFO) << "  fe_logical:  " << ext->fe_logical;
    LOG(INFO) << "  fe_physical: " << ext->fe_physical;
    LOG(INFO) << "  fe_length:   " << ext->fe_length;
    LOG(INFO) << "  fe_flags:    0x" << std::hex << ext->fe_flags;
}

bool FiemapWriter::ReadFiemap(int file_fd, const std::string& file_path) {
    uint64_t fiemap_size =
            sizeof(struct fiemap_extent) + kMaxExtents * sizeof(struct fiemap_extent);
    auto buffer = std::unique_ptr<void, decltype(&free)>(calloc(1, fiemap_size), free);
    if (buffer == nullptr) {
        LOG(ERROR) << "Failed to allocate memory for fiemap";
        return false;
    }

    struct fiemap* fiemap = reinterpret_cast<struct fiemap*>(buffer.get());
    fiemap->fm_start = 0;
    fiemap->fm_length = UINT64_MAX;
    // make sure file is synced to disk before we read the fiemap
    fiemap->fm_flags = FIEMAP_FLAG_SYNC;
    fiemap->fm_extent_count = kMaxExtents;

    if (ioctl(file_fd, FS_IOC_FIEMAP, fiemap)) {
        PLOG(ERROR) << "Failed to get FIEMAP from the kernel for file: " << file_path;
        return false;
    }

    if (fiemap->fm_mapped_extents == 0) {
        LOG(ERROR) << "File " << file_path << " has zero extents";
        return false;
    }

    // Iterate through each extent read and make sure its valid before adding it to the vector
    bool last_extent_seen = false;
    struct fiemap_extent* extent = &fiemap->fm_extents[0];
    for (uint32_t i = 0; i < fiemap->fm_mapped_extents; i++, extent++) {
        if (extent->fe_flags & kUnsupportedExtentFlags) {
            LOG(ERROR) << "Extent " << i + 1 << " of file " << file_path
                       << " has unsupported flags";
            LogExtent(extent);
            fiemap_.clear();
            return false;
        }

        if (extent->fe_flags & FIEMAP_EXTENT_LAST) {
            last_extent_seen = true;
            if (i != (fiemap->fm_mapped_extents - 1)) {
                LOG(WARNING) << "Extents are being received out-of-order";
            }
        }

        fiemap_.emplace_back(std::move(*extent));
    }

    if (!last_extent_seen) {
        // The file is possibly too fragmented.
        if (fiemap->fm_mapped_extents == kMaxExtents) {
            LOG(ERROR) << "File is too fragmented, needs more than " << kMaxExtents << " extents.";
        }
        fiemap_.clear();
    }

    return last_extent_seen;
}

bool FiemapWriter::AllocateFileWithSize(int file_fd, const std::string& file_path, int bdev_fd,
                                        const std::string& bdev_path, uint64_t file_size) {
    // sets up block_size_
    if (!PerformBlockDevChecks(bdev_fd, bdev_path, file_size)) {
        return false;
    }

    // sets up fs_type_
    if (!PerformFsChecks(file_fd, file_path, file_size)) {
        return false;
    }

    // Reserve space for the file on the file system and write it out to make sure the extents
    // don't come back unwritten. Return from this function with the kernel file offset set to 0.
    // If the filesystem is f2fs, then we also PIN the file on disk to make sure the blocks
    // aren't moved around.
    if (fallocate(file_fd, FALLOC_FL_ZERO_RANGE, 0, file_size)) {
        PLOG(ERROR) << "Failed to allocate space for file: " << file_path << " size: " << file_size;
        return false;
    }

    // write zeroes in 'block_size_' bytes until we reach file_size_ to make sure the data
    // blocks are actually written to by the file system and thus getting rid of the holes in the
    // file.
    auto buffer = std::unique_ptr<void, decltype(&free)>(calloc(1, block_size_), free);
    if (buffer == nullptr) {
        LOG(ERROR) << "failed to allocate memory for writing file";
        return false;
    }

    off64_t offset = lseek64(file_fd, 0, SEEK_SET);
    if (offset < 0) {
        PLOG(ERROR) << "Failed to seek at the beginning of : " << file_path;
        return false;
    }

    for (; offset < file_size; offset += block_size_) {
        if (!::android::base::WriteFully(file_fd, buffer.get(), block_size_)) {
            PLOG(ERROR) << "Failed to write" << block_size_ << " bytes at offset" << offset
                        << " in file " << file_path;
            return false;
        }
    }

    if (lseek64(file_fd, 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "Failed to reset offset at the beginning of : " << file_path;
        return false;
    }

    // flush all writes here ..
    if (fsync(file_fd)) {
        PLOG(ERROR) << "Failed to synchronize written file:" << file_path;
        return false;
    }

    // f2fs may move the file blocks around.
    if (!PinFile(file_fd, file_path)) {
        LOG(ERROR) << "Failed to pin the file in storage";
        return false;
    }

    return true;
}

}  // namespace fiemap_writer
}  // namespace android
