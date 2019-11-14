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

using android::f2fs_pin::kF2fsBlockSize;
using android::f2fs_pin::kF2fsSegmentSize;

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

class Args {
  public:
    Args() {
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
        if (sfs.f_bsize != kF2fsBlockSize) {
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

Args args;

// Big file test

TEST(LibF2fsPinTest, BigFile) {
    const char* dir = args.getDir();
    const char* bdev = args.getBdev();
    const char* file = args.getTestFile();
    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * kF2fsSegmentSize);

    off_t big_file_free_space_capped = 1 << 30;
    if (free_space > big_file_free_space_capped) free_space = big_file_free_space_capped;

    off_t file_size = free_space - 4096 - (free_space >> 10);
    file_size &= ~(kF2fsSegmentSize - 1);

    ASSERT_TRUE(Create(bdev, file, file_size, false));
    ASSERT_TRUE(Ensure(bdev, file, false));
    (void)unlink(file);
}

class Param {
  public:
    Param(bool verify, off_t file_size) {
        verify_ = verify;
        file_size_ = file_size;
    }
    bool verify_;
    off_t file_size_;
};

class LibF2fsPinWithGrowthTest : public ::testing::TestWithParam<Param> {};

TEST_P(LibF2fsPinWithGrowthTest, CreateEnsureGrowExpectEnsureError) {
    Param param = GetParam();
    const char* dir = args.getDir();
    const char* bdev = args.getBdev();
    const char* file = args.getTestFile();

    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * kF2fsSegmentSize);

    ASSERT_TRUE(Create(bdev, file, param.file_size_, param.verify_));
    ASSERT_TRUE(Ensure(bdev, file, param.verify_));
    ASSERT_TRUE(WriteOneByte(file, param.file_size_));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

class ParamWithHole {
  public:
    ParamWithHole(bool verify, off_t file_size, off_t hole_size, off_t hole_offset) {
        verify_ = verify;
        file_size_ = file_size;
        hole_size_ = hole_size;
        hole_offset_ = hole_offset;
    }
    bool verify_;
    off_t file_size_;
    off_t hole_size_;
    off_t hole_offset_;
};

class LibF2fsPinWithHoleTest : public ::testing::TestWithParam<ParamWithHole> {};

TEST_P(LibF2fsPinWithHoleTest, CreateEnsurePunchHoleExpectEnsureError) {
    ParamWithHole param = GetParam();
    const char* dir = args.getDir();
    const char* bdev = args.getBdev();
    const char* file = args.getTestFile();

    off_t free_space = 0;
    ASSERT_TRUE(GetCwdFreeSpace(dir, &free_space));
    ASSERT_GE(free_space, 20 * kF2fsSegmentSize);

    ASSERT_TRUE(Create(bdev, file, param.file_size_, param.verify_));
    ASSERT_TRUE(Ensure(bdev, file, param.verify_));
    ASSERT_TRUE(PunchHoleAndFsync(file, param.hole_offset_, param.hole_size_));
    ASSERT_TRUE(EnsureExpectingErrors(bdev, file));
    (void)unlink(file);
}

// Tests with single segment sized files

INSTANTIATE_TEST_SUITE_P(UnverifiedSegmentSizedFileWithGrowthAfterPin, LibF2fsPinWithGrowthTest,
                         testing::Values(Param(false, kF2fsSegmentSize)));

INSTANTIATE_TEST_SUITE_P(VerifiedSegmentSizedFileWithBlockSizedHoleAtZero, LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(true, kF2fsSegmentSize, kF2fsBlockSize, 0)));

INSTANTIATE_TEST_SUITE_P(UnverifiedSegmentSizedFileWithBlockSizedHoleBeforeEof,
                         LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(false, kF2fsSegmentSize, kF2fsBlockSize,
                                                       kF2fsSegmentSize - kF2fsBlockSize)));

INSTANTIATE_TEST_SUITE_P(UnverifiedSegmentSizedFileWithBlockSizedHoleHalfSegmentIntoFile,
                         LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(false, kF2fsSegmentSize, kF2fsBlockSize,
                                                       kF2fsSegmentSize / 2)));

// Tests with 2 x segment sized files

INSTANTIATE_TEST_SUITE_P(Unverified2xSegmentSizedFileWithGrowthAfterPin, LibF2fsPinWithGrowthTest,
                         testing::Values(Param(false, 2 * kF2fsSegmentSize)));

INSTANTIATE_TEST_SUITE_P(Verified2xSegmentSizedFileWithBlockSizedHoleAtZero, LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(true, 2 * kF2fsSegmentSize, kF2fsBlockSize,
                                                       0)));

INSTANTIATE_TEST_SUITE_P(Unverified2xSegmentSizedFileWithBlockSizedHoleBeforeEof,
                         LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(false, 2 * kF2fsSegmentSize, kF2fsBlockSize,
                                                       2 * kF2fsSegmentSize - kF2fsBlockSize)));

INSTANTIATE_TEST_SUITE_P(Unverified2xSegmentSizedFileWithBlockSizedHoleHalfSegmentIntoFile,
                         LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(false, 2 * kF2fsSegmentSize, kF2fsBlockSize,
                                                       kF2fsSegmentSize / 2)));

INSTANTIATE_TEST_SUITE_P(Unverified2xSegmentSizedFileWithBlockSizedHoleAtStartOf2ndSegment,
                         LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(false, 2 * kF2fsSegmentSize, kF2fsBlockSize,
                                                       kF2fsSegmentSize)));

INSTANTIATE_TEST_SUITE_P(Unverified2xSegmentSizedFileWithSegmentSizedHoleIn2ndSegment,
                         LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(false, 2 * kF2fsSegmentSize,
                                                       kF2fsSegmentSize, kF2fsSegmentSize)));

// Tests with 4 x segment sized files

INSTANTIATE_TEST_SUITE_P(Unverified4xSegmentSizedFileWithGrowthAfterPin, LibF2fsPinWithGrowthTest,
                         testing::Values(Param(false, 4 * kF2fsSegmentSize)));

INSTANTIATE_TEST_SUITE_P(Verified4xSegmentSizedFileWithBlockSizedHoleAtZero, LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(true, 4 * kF2fsSegmentSize, kF2fsBlockSize,
                                                       0)));

INSTANTIATE_TEST_SUITE_P(Unverified4xSegmentSizedFileWithBlockSizedHoleBeforeEof,
                         LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(false, 4 * kF2fsSegmentSize, kF2fsBlockSize,
                                                       4 * kF2fsSegmentSize - kF2fsBlockSize)));

INSTANTIATE_TEST_SUITE_P(Unverified4xSegmentSizedFileWithBlockSizedHoleHalfSegmentIntoFile,
                         LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(false, 4 * kF2fsSegmentSize, kF2fsBlockSize,
                                                       kF2fsSegmentSize / 2)));

INSTANTIATE_TEST_SUITE_P(Unverified4xSegmentSizedFileWithBlockSizedHoleAtStartOf2ndSegment,
                         LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(false, 4 * kF2fsSegmentSize, kF2fsBlockSize,
                                                       kF2fsSegmentSize)));

INSTANTIATE_TEST_SUITE_P(Unverified4xSegmentSizedFileWithSegmentSizedHoleIn2ndSegment,
                         LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(false, 4 * kF2fsSegmentSize,
                                                       kF2fsSegmentSize, kF2fsSegmentSize)));

INSTANTIATE_TEST_SUITE_P(Unverified4xSegmentSizedFileWithSegmentSizedHoleBeforeEof,
                         LibF2fsPinWithHoleTest,
                         testing::Values(ParamWithHole(false, 4 * kF2fsSegmentSize,
                                                       kF2fsSegmentSize, 3 * kF2fsSegmentSize)));
