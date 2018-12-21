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
        return false;
    }

    std::string bdev_path;
    if (!FileToBlockDevPath(abs_path, &bdev_path)) {
        LOG(ERROR) << "Failed to get block_dev path for file: " << file_path;
        return false;
    }

    ::android::base::unique_fd bdev_fd(
            TEMP_FAILURE_RETRY(open(bdev_path.c_str(), O_RDWR | O_CLOEXEC)));
    if (bdev_fd < 0) {
        PLOG(ERROR) << "Failed to open block device: " << bdev_path;
        return false;
    }

    if (!PerformBlockDevChecks(bdev_fd.get(), bdev_path, file_size)) {
        return false;
    }

    if (!PerformFsChecks(file_fd.get(), file_path, file_size)) {
        return false;
    }

    // fallocate file here
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

const std::vector<std::unique_ptr<struct fiemap_extent>>& FiemapWriter::Fiemap() {
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
        LOG(ERROR) << "File size: " << file_size << " is not aligned to block size: " << blksz
                   << " of: " << bdev_path;
        return false;
    }

    return true;
}

bool FiemapWriter::PerformFsChecks(int file_fd, const std::string& file_path, uint64_t file_size) {
    struct statfs64 sfs;
    if (fstatfs64(file_fd, &sfs)) {
        PLOG(ERROR) << "Failed to read file system status at: " << file_path;
        return false;
    }

    // check if the filesystem is of supported types.
    // Only ext4 and f2fs are tested and supported.
    if ((sfs.f_type != EXT4_SUPER_MAGIC) && (sfs.f_type != F2FS_SUPER_MAGIC)) {
        LOG(ERROR) << "Unsupported file system type: 0x" << std::hex << sfs.f_type;
        return false;
    }

    uint64_t available_bytes = sfs.f_bsize * sfs.f_bavail;
    if (available_bytes <= file_size) {
        LOG(ERROR) << "Not enough free space in file system to create file of size:" << file_size;
        return false;
    }

    // TODO: check if free space is equal or above given threshold
    return true;
}

}  // namespace fiemap_writer
}  // namespace android
