/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "pin_misc.h"

#include <android-base/logging.h>
#include <errno.h>
#include <iostream>

//  Write (through the file system) a pattern of uint64_t: 0, 1, 2, ...

bool WritePattern(const char* file, int file_fd, off_t file_size) {
    SectorAlignedMemory mem;
    constexpr size_t kBlockSize = mem.kSize;
    uint64_t* block = mem.Address();
    uint64_t* end = block + kBlockSize / sizeof(uint64_t);
    uint64_t value = 0;

    for (off_t remaining = file_size; remaining > 0;) {
        for (uint64_t* p = block; p < end;) *p++ = value++;
        size_t n = remaining > kBlockSize ? kBlockSize : remaining;
        ssize_t written = write(file_fd, block, n);
        if (written != n) {
            if (written < 0)
                PLOG(ERROR) << "write() failed: " << file;
            else
                LOG(ERROR) << "partial write(): " << file;
            return false;
        }
        remaining -= written;
    }
    if (fsync(file_fd) < 0) {
        LOG(ERROR) << "fsync() failed: " << file;
        return false;
    }
    return true;
}

//  Read file from the bdev and verify a pattern of uint64_t: 0, 1, 2, ...

bool VerifyPattern(const char* bdev, int bdev_fd, const char* file, int file_fd, off_t file_size) {
    SectorAlignedMemory mem;
    constexpr size_t kBlockSize = mem.kSize;
    uint64_t* block = mem.Address();
    uint64_t value = 0;

    for (off_t offset = 0; offset < file_size;) {
        off_t leftover = file_size - offset;

        auto result_extent_map = android::f2fs_pin::FileGetExtentMap(file_fd, offset, leftover);
        if (!result_extent_map) {
            LOG(ERROR) << "could not get extent map: " << result_extent_map.error();
            return false;
        }
        android::f2fs_pin::ExtentMap em = result_extent_map.value();
        android::f2fs_pin::FiemapExtent* fe = em.em_fiemap.fm_extents;

        if (fe->fe_logical != offset) {
            LOG(ERROR) << "file should not have holes: " << file;
            return false;
        }

        off_t length = fe->fe_length;
        off_t physical = fe->fe_physical;

        while (length > 0) {
            size_t n = length > kBlockSize ? kBlockSize : length;
            ssize_t nread = pread(bdev_fd, block, n, physical);
            if (nread != n) {
                if (nread < 0)
                    PLOG(ERROR) << "pread() failed: " << bdev;
                else
                    LOG(ERROR) << "partial read(): " << bdev;
                return false;
            }
            uint64_t* end = block + n / sizeof(uint64_t);
            for (uint64_t* p = block; p < end; ++p, ++value)
                if (*p != value) {
                    LOG(ERROR) << "wrong data when reading file directly from device: " << file;
                    return false;
                }
            physical += n;
            length -= n;
        }

        offset += fe->fe_length;
        leftover -= fe->fe_length;
    }
    return true;
}

bool EnsurePinned(const char* bdev, const char* file, bool verify_file) {
    android::base::unique_fd bdev_fd(open(bdev, O_RDONLY | O_DIRECT | O_CLOEXEC));
    if (bdev_fd < 0) {
        PLOG(ERROR) << "could not open block device: " << bdev;
        return false;
    }
    android::base::unique_fd file_fd(open(file, O_RDONLY | O_CLOEXEC));
    if (file_fd < 0) {
        PLOG(ERROR) << "could not open file: " << file;
        return false;
    }
    std::string bdev_string(bdev);
    auto res = android::f2fs_pin::FileEnsureReliablyPinned(file_fd, bdev_fd, bdev_string);
    if (!res) {
        LOG(ERROR) << "FileEnsureReliablyPinned() failed: " << res.error();
        return false;
    }
    if (!verify_file) return true;

    struct stat st;
    if (fstat(file_fd, &st) < 0) {
        PLOG(ERROR) << "fstat() failed: " << file;
        return false;
    }
    off_t file_size = st.st_size;
    return VerifyPattern(bdev, bdev_fd, file, file_fd, file_size);
}

bool CreatePinned(const char* bdev, const char* file, off_t file_size, bool init_file) {
    android::base::unique_fd bdev_fd(open(bdev, O_RDONLY | O_DIRECT | O_CLOEXEC));
    if (bdev_fd < 0) {
        PLOG(ERROR) << "could not open block device: " << bdev;
        return false;
    }
    android::base::unique_fd file_fd(open(file, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    if (file_fd < 0) {
        PLOG(ERROR) << "could not create file: " << file;
        return false;
    }
    std::string bdev_string(bdev);
    auto res = android::f2fs_pin::FileAllocateSpaceAndReliablyPin(file_fd, bdev_fd, bdev_string,
                                                                  file_size);
    if (!res) {
        LOG(ERROR) << "FileAllocateSpaceAndReliablyPin() failed: " << res.error();
        return false;
    }
    if (!init_file) return true;

    if (!WritePattern(file, file_fd, file_size)) return false;
    res = android::f2fs_pin::FileEnsureReliablyPinned(file_fd, bdev_fd, bdev_string);
    if (!res) {
        LOG(ERROR) << "file not reliably pinned after writing into it: " << res.error();
        return false;
    }
    return VerifyPattern(bdev, bdev_fd, file, file_fd, file_size);
}
