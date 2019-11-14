/*
 * Copyright (C) 2018-2020 The Android Open Source Project
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

#include "libf2fs_pin/pin.h"
#include "pin_impl.h"
#include "pin_misc.h"

#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

bool Ensure(const char* bdev, const char* file, bool verify_file) {
    bool result = EnsurePinned(bdev, file, verify_file);
    if (!result) (void)unlink(file);
    return result;
}

bool Create(const char* bdev, const char* file, off_t file_size, bool init_file) {
    bool result = CreatePinned(bdev, file, file_size, init_file);
    if (!result) (void)unlink(file);
    return result;
}

bool EnsureExpectingErrors(const char* bdev, const char* file) {
    android::base::unique_fd bdev_fd(open(bdev, O_RDONLY | O_DIRECT | O_CLOEXEC));
    if (bdev_fd < 0) {
        PrintErrno("could not open block device", bdev);
        (void)unlink(file);
        return false;
    }
    android::base::unique_fd file_fd(open(file, O_RDONLY | O_CLOEXEC));
    if (file_fd < 0) {
        PrintErrno("could not open file", file);
        (void)unlink(file);
        return false;
    }
    std::string bdev_string(bdev);
    auto result = android::f2fs_pin::FileEnsureReliablyPinned(file_fd, bdev_fd, bdev_string);
    if (result) {
        PrintError("expected FileEnsureReliablyPinned() to fail, it did not", file);
        (void)unlink(file);
        return false;
    }
    return true;
}

bool WriteOneByte(const char* file, off_t offset) {
    android::base::unique_fd file_fd(open(file, O_RDWR | O_CLOEXEC));
    if (file_fd < 0) {
        PrintErrno("could not open file", file);
        return false;
    }
    if (pwrite(file_fd, "x", 1, offset) != 1) {
        PrintErrno("could not write one byte", file);
        (void)unlink(file);
        return false;
    }
    return true;
}

bool PunchHoleAndFsync(const char* file, off_t offset, off_t length) {
    android::base::unique_fd file_fd(open(file, O_RDWR | O_CLOEXEC));
    if (file_fd < 0) {
        PrintErrno("could not open file", file);
        (void)unlink(file);
        return false;
    }
    if (fallocate(file_fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, length) < 0) {
        PrintErrno("could not punch hole in file", file);
        (void)unlink(file);
        return false;
    }
    if (fsync(file_fd) == -1) {
        PrintErrno("could not fsync file", file);
        (void)unlink(file);
        return false;
    }
    return true;
}

bool GetCwdFreeSpace(const char* dir, off_t* space) {
    struct statfs sfs;
    if (statfs(".", &sfs) < 0) {
        PrintErrno("statfs() failed", dir);
        *space = 0;
        return false;
    }
    *space = sfs.f_bfree * sfs.f_bsize;
    return true;
}

class Params {
  public:
    Params() {
        have_f2fs_fs_ = false;

        const char* mounts_name = "/proc/mounts";
        std::ifstream mounts_stream(mounts_name, std::ios::binary);
        if (!mounts_stream.is_open()) {
            std::cerr << "could not open " << mounts_name << "\n";
            return;
        }

        std::string bdev;
        std::string dir;

        bool found = false;
        while (!mounts_stream.eof()) {
            std::string type;
            std::string rest;
            mounts_stream >> bdev >> dir >> type;
            if (mounts_stream.eof()) return;
            std::getline(mounts_stream, rest);
            if (dir == "/data" && type == "f2fs") {
                found = true;
                break;
            }
        }
        if (!found) return;

        const char* cdir = dir.c_str();
        if (chdir(cdir) < 0) {
            PrintErrno("chdir() failed", cdir);
        }
        struct statfs sfs;
        if (statfs(".", &sfs) < 0) {
            PrintErrno("statfs() failed", cdir);
            return;
        }
        if (sfs.f_type != F2FS_SUPER_MAGIC) {
            PrintError("stafs() not a F2FS fs", cdir);
            return;
        }
        if (sfs.f_bsize != android::f2fs_pin::kF2fsBlockSize) {
            PrintError("stafs() invalid f_bsize", cdir);
            return;
        }

        dir_ = dir;
        bdev_ = bdev;
        have_f2fs_fs_ = true;
    }

    bool haveF2fsFs() { return have_f2fs_fs_; }
    const char* getDir() { return dir_.c_str(); }
    const char* getBdev() { return bdev_.c_str(); }
    const char* getTestFile() { return "pin_test_file.data"; }

  private:
    bool have_f2fs_fs_;
    std::string dir_;
    std::string bdev_;
};

Params params;

TEST(LibF2fsPinTest, BigFile) {
    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * android::f2fs_pin::kF2fsSegmentSize);

    off_t big_file_free_space_capped = 1 << 30;
    if (free_space > big_file_free_space_capped) free_space = big_file_free_space_capped;

    off_t file_size = free_space - 4096 - (free_space >> 10);
    file_size &= ~(android::f2fs_pin::kF2fsSegmentSize - 1);

    ASSERT_TRUE(Create(bdev, file, file_size, false));
    ASSERT_TRUE(Ensure(bdev, file, false));
    (void)unlink(file);
}

// Tests with single segment sized files

TEST(LibF2fsPinTest, VerifiedSegmentSizedFileWithBlockSizedHoleAtZero) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    constexpr off_t file_size = segment_size;
    bool verify = true;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, 0, block_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, UnverifiedSegmentSizedFileWithBlockSizedHoleBeforeEof) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, file_size - block_size, block_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, UnverifiedSegmentSizedFileWithBlockSizedHoleHalfSegmentIntoFile) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, segment_size / 2, block_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, UnverifiedSegmentSizedFileWithGrowthAfterPin) {
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(WriteOneByte(file, file_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

// Tests with 2 x segment sized files

TEST(LibF2fsPinTest, Verified2xSegmentSizedFileWithBlockSizedHoleAtZero) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    constexpr off_t file_size = 2 * segment_size;
    bool verify = true;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, 0, block_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, Unverified2xSegmentSizedFileWithBlockSizedHoleBeforeEof) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = 2 * segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, file_size - block_size, block_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, Unverified2xSegmentSizedFileWithBlockSizedHoleHalfSegmentIntoFile) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = 2 * segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, segment_size / 2, block_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, Unverified2xSegmentSizedFileWithBlockSizedHoleAtStartOf2ndSegment) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = 2 * segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, segment_size, block_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, Unverified2xSegmentSizedFileWithSegmentSizedHoleIn2ndSegment) {
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = 2 * segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, segment_size, segment_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

// Tests with 4 x segment sized files

TEST(LibF2fsPinTest, Verified4xSegmentSizedFileWithBlockSizedHoleAtZero) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    constexpr off_t file_size = 4 * segment_size;
    bool verify = true;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, 0, block_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, Unverified4xSegmentSizedFileWithBlockSizedHoleBeforeEof) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = 4 * segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, file_size - block_size, block_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, Unverified4xSegmentSizedFileWithBlockSizedHoleHalfSegmentIntoFile) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = 4 * segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, segment_size / 2, block_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, Unverified4xSegmentSizedFileWithBlockSizedHoleAtStartOf2ndSegment) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = 4 * segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, segment_size, block_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, Unverified4xSegmentSizedFileWithSegmentSizedHoleIn2ndSegment) {
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = 4 * segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, segment_size, segment_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

TEST(LibF2fsPinTest, Unverified4xSegmentSizedFileWithSegmentSizedHoleBeforeEof) {
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    off_t file_size = 4 * segment_size;
    bool verify = false;

    const char* dir = params.getDir();
    const char* bdev = params.getBdev();
    const char* file = params.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * segment_size);

    ASSERT_TRUE(Create(bdev, file, file_size, verify));
    ASSERT_TRUE(Ensure(bdev, file, verify));
    ASSERT_TRUE(PunchHoleAndFsync(file, segment_size, segment_size));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}
