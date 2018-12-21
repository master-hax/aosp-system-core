/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#pragma once

#include <linux/fiemap.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <android-base/unique_fd.h>

namespace android {
namespace fiemap_writer {

class FiemapWriter final {
  public:
    static constexpr const char* kSysDevBlock = "/sys/dev/block";
    static constexpr const char* kBlockDevDir = "/dev/block";

    FiemapWriter() : file_size_(0), file_offset_(0), fs_type_(0), block_size_(0){};

    bool Create(const std::string& file_path, uint64_t size);

    // Block size of the underlying block device. The size passed in Read / Write / Append
    // must be aligned to this block size. The caller is expected to manage the alignment.
    uint64_t BlockSize() const;

    // Syncs block device writes.
    void Flush() const;

    // Returns FIEMAP of the underlying file as read from the kernel.
    const std::vector<std::unique_ptr<struct fiemap_extent>>& Fiemap();

    // Works like pwrite(), except for the file descriptor is private to the class.
    // The return value is success / failure. This will happen in particular if the
    // kernel write returns errors, extents are not writeable or more importantly, if the 'size' is
    // not aligned to the block device's block size.
    bool Write(off64_t off, uint8_t* buffer, uint64_t size);

    // Same as Write(), except, starts writing from the last offset.
    bool Append(uint8_t* buffer, uint64_t size);

    // The counter part of Write(). However, unaligned reads will result in error.
    // In case of error, the contents of buffer MUST be discarded.
    bool Read(off64_t off, uint8_t* buffer, uint64_t size);

    ~FiemapWriter() = default;

    const std::string& file_path() const { return file_path_; };
    uint64_t size() const { return file_size_; };
    const std::string& bdev_path() const { return bdev_path_; };

  private:
    // Name of the file managed by this class.
    std::string file_path_;
    // Block device on which we have created the file.
    std::string bdev_path_;

    // File descriptors for the file and block device
    ::android::base::unique_fd file_fd_;
    ::android::base::unique_fd bdev_fd_;

    // Size in bytes of the file this class is writing
    uint64_t file_size_;

    // Current offset we are writing at
    off64_t file_offset_;

    // Filesystem type where the file is being created.
    // See: <uapi/linux/magic.h> for filesystem magic numbers
    uint32_t fs_type_;

    // Blocksize as reported by the kernel of the underlying block device;
    uint64_t block_size_;

    // This file's fiemap
    std::vector<std::unique_ptr<struct fiemap_extent>> fiemap_;

    // Non-copyable & Non-movable
    FiemapWriter(const FiemapWriter&) = delete;
    FiemapWriter& operator=(const FiemapWriter&) = delete;
    FiemapWriter& operator=(FiemapWriter&&) = delete;
    FiemapWriter(FiemapWriter&&) = delete;

    // private helpers
    bool BlockDevToName(uint32_t major, uint32_t minor, std::string* name);
    void Cleanup(const std::string& file_path);
    bool FileToBlockDevPath(const std::string& file, std::string* bdev_path);

    bool PerformBlockDevChecks(int bdev_fd, const std::string& bdev_path, uint64_t file_size);
    bool PerformFsChecks(int file_fd, const std::string& file_path, uint64_t file_size);
    bool PinFile(int file_fd, const std::string& file_path);
    bool PinFileStatus(int file_fd, const std::string& file_path);

    bool AllocateFileWithSize(int file_fd, const std::string& file_path, int bdev_fd,
                              const std::string& bdev_path, uint64_t file_size);
};

}  // namespace fiemap_writer
}  // namespace android
