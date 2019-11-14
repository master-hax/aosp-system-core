/*
 * Copyright (C) 2018-2019 The Android Open Source Project
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

#include "f2fs_pin/pin.h"
#include "pin_impl.h"

#include <assert.h>
#include <errno.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define STOP() stop(__FUNCTION__, __LINE__)

void stop(const char* function, int line) {
    std::cerr << "Function: " << function << ", line: " << line << "\n";
    std::cerr << "enter some text to continue (or control-C to abort): ";
    char enter[1024];
    std::cin >> enter;
}

void PrintError(const char* cmd, const char* msg1, const char* msg2) {
    std::cerr << cmd << ": " << msg1 << ": " << msg2 << "\n";
}

void PrintErrno(const char* cmd, const char* msg1, const char* msg2) {
    int error = errno;  // save errno in case it gets clobbered internally by output
    std::cerr << cmd << ": " << msg1 << ": " << msg2;
    if (error) std::cerr << ": " << strerror(error);
    std::cerr << "\n";
}

android::f2fs_pin::Result ResultExtentMapToResult(android::f2fs_pin::ResultExtentMap r) {
    if (!r) return r.error();
    return {};
}

void PrintErrorResult(const char* cmd, const char* msg, const android::f2fs_pin::Result& result) {
    std::cerr << cmd << ": " << msg << ": " << result.error();
    std::cerr << "\n";
}

//  Read write from some devices fails unless the memory buffer address is sector aligned

class SectorAlignedMemory {
  public:
    static constexpr size_t kSectorSize = 4096;
    static constexpr size_t kSize = 64 * 1024;
    uint64_t* Address() {
        uintptr_t va = (uintptr_t)mem;
        va &= ~(kSectorSize - 1);  // ensure va is kSectorSize aligned
        va += kSectorSize;         // ensure it is inside mem[]
        return (uint64_t*)va;
    }

  private:
    uint64_t mem[kSize / sizeof(uint64_t) + kSectorSize];  // extra sector to align
};

//  Write (through the file system) a pattern of uint64_t: 0, 1, 2, ...

bool WritePattern(const char* cmd, const char* file, int file_fd, off_t file_size) {
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
                PrintErrno(cmd, "write() failed", file);
            else
                PrintError(cmd, "partial write()", file);
            return false;
        }
        remaining -= written;
    }
    if (fsync(file_fd) < 0) {
        PrintError(cmd, "fsync() failed", file);
        return false;
    }
    return true;
}

//  Read file from the bdev and verify a pattern of uint64_t: 0, 1, 2, ...

bool VerifyPattern(const char* cmd, const char* bdev, int bdev_fd, const char* file, int file_fd,
                   off_t file_size) {
    SectorAlignedMemory mem;
    constexpr size_t kBlockSize = mem.kSize;
    uint64_t* block = mem.Address();
    uint64_t value = 0;

    for (off_t offset = 0; offset < file_size;) {
        off_t leftover = file_size - offset;

        auto result_extent_map = android::f2fs_pin::FileGetExtentMap(file_fd, offset, leftover);
        if (!result_extent_map) {
            PrintErrorResult(cmd, "could not get extent map",
                             ResultExtentMapToResult(result_extent_map));
            return false;
        }
        android::f2fs_pin::ExtentMap em = result_extent_map.value();
        android::f2fs_pin::FiemapExtent* fe = em.em_fiemap.fm_extents;

        if (fe->fe_logical != offset) {
            PrintError(cmd, "file should not have holes", file);
            return false;
        }

        off_t length = fe->fe_length;
        off_t physical = fe->fe_physical;

        while (length > 0) {
            size_t n = length > kBlockSize ? kBlockSize : length;
            ssize_t nread = pread(bdev_fd, block, n, physical);
            if (nread != n) {
                if (nread < 0)
                    PrintErrno(cmd, "pread() failed", bdev);
                else
                    PrintError(cmd, "partial read()", bdev);
                return false;
            }
            uint64_t* end = block + n / sizeof(uint64_t);
            for (uint64_t* p = block; p < end; ++p, ++value)
                if (*p != value) {
                    PrintError(cmd, "wrong data when reading file directly from device", file);
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

bool CommandEnsure(const char* cmd, const char* bdev, const char* file, bool verify_file) {
    android::base::unique_fd bdev_fd(open(bdev, O_RDONLY | O_DIRECT | O_CLOEXEC));
    if (bdev_fd < 0) {
        PrintErrno(cmd, "could not open block device", bdev);
        return false;
    }
    android::base::unique_fd file_fd(open(file, O_RDONLY | O_CLOEXEC));
    if (file_fd < 0) {
        PrintErrno(cmd, "could not open file", file);
        return false;
    }

    std::string bdev_string(bdev);
    auto result = android::f2fs_pin::FileEnsureReliablyPinned(file_fd, bdev_fd, bdev_string);
    if (!result) {
        PrintErrorResult(cmd, "FileEnsureReliablyPinned() failed", result);
        return false;
    }

    if (!verify_file) return true;

    struct stat st;
    if (fstat(file_fd, &st) < 0) {
        PrintErrno(cmd, "fstat() failed", file);
        return false;
    }
    off_t file_size = st.st_size;

    return VerifyPattern(cmd, bdev, bdev_fd, file, file_fd, file_size);
}

bool CommandCreate(const char* cmd, const char* bdev, const char* file, off_t file_size,
                   bool init_file) {
    android::base::unique_fd bdev_fd(open(bdev, O_RDONLY | O_DIRECT | O_CLOEXEC));
    if (bdev_fd < 0) {
        PrintErrno(cmd, "could not open block device", bdev);
        return false;
    }
    android::base::unique_fd file_fd(open(file, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    if (file_fd < 0) {
        PrintErrno(cmd, "could not create file", file);
        return false;
    }

    std::string bdev_string(bdev);
    auto result = android::f2fs_pin::FileAllocateSpaceAndReliablyPin(file_fd, bdev_fd, bdev_string,
                                                                     file_size);
    if (!result) {
        PrintErrorResult(cmd, "FileAllocateSpaceAndReliablyPin() failed", result);
        return false;
    }

    if (!init_file) return true;

    if (!WritePattern(cmd, file, file_fd, file_size)) return false;

    result = android::f2fs_pin::FileEnsureReliablyPinned(file_fd, bdev_fd, bdev_string);
    if (!result) {
        PrintErrorResult(cmd, "file not reliably pinned after writing into it", result);
        return false;
    }

    return VerifyPattern(cmd, bdev, bdev_fd, file, file_fd, file_size);
}

bool CommandEnsureExpectingErrors(const char* cmd, const char* bdev, const char* file) {
    android::base::unique_fd bdev_fd(open(bdev, O_RDONLY | O_DIRECT | O_CLOEXEC));
    if (bdev_fd < 0) {
        PrintErrno(cmd, "could not open block device, should not, aborting remaining tests", bdev);
        exit(1);
    }
    android::base::unique_fd file_fd(open(file, O_RDONLY | O_CLOEXEC));
    if (file_fd < 0) {
        PrintErrno(cmd, "could not open file, should not, aborting remaining tests", file);
        exit(1);
    }
    std::string bdev_string(bdev);
    auto result = android::f2fs_pin::FileEnsureReliablyPinned(file_fd, bdev_fd, bdev_string);
    if (!result) {
        return false;
    }
    return true;
}

bool WriteOneByte(const char* cmd, const char* file, off_t offset) {
    android::base::unique_fd file_fd(open(file, O_RDWR | O_CLOEXEC));
    if (file_fd < 0) {
        PrintErrno(cmd, "could not open file, aborting tests", file);
        exit(1);
    }
    if (pwrite(file_fd, "x", 1, offset) != 1) return false;
    return true;
}

void Ftruncate(const char* cmd, const char* file, off_t file_size) {
    android::base::unique_fd file_fd(open(file, O_RDWR | O_CLOEXEC));
    if (file_fd < 0) {
        PrintErrno(cmd, "could not open file, aborting tests", file);
        exit(1);
    }
    if (ftruncate(file_fd, file_size) < 0) {
        PrintErrno(cmd, "could not truncate file, aborting tests", file);
        exit(1);
    }
}

void PunchHoleAndFsync(const char* cmd, const char* file, off_t offset, off_t length) {
    android::base::unique_fd file_fd(open(file, O_RDWR | O_CLOEXEC));
    if (file_fd < 0) {
        PrintErrno(cmd, "could not open file, aborting tests", file);
        exit(1);
    }
    if (fallocate(file_fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, length) < 0) {
        PrintErrno(cmd, "could not punch hole in file, aborting tests", file);
        exit(1);
    }
    if (fsync(file_fd) == -1) {
        PrintErrno(cmd, "could not fsync file, aborting tests", file);
        exit(1);
    }
}

void TestStop() {}

int test_stop = 0;

void TestCount(int* test_count) {
    ++*test_count;
    if (*test_count == test_stop) TestStop();
}

bool Test(const char* cmd, const char* bdev, const char* file, off_t file_size, int* test_count) {
    TestCount(test_count);
    bool success = CommandCreate(cmd, bdev, file, file_size, false);
    if (!success) {
        PrintError(cmd, "could not create, allocate, and pin file", file);
        (void)unlink(file);
        return false;
    }

    TestCount(test_count);
    success = CommandEnsure(cmd, bdev, file, false);
    if (!success) PrintError(cmd, "could not verify file", file);
    if (unlink(file) < 0) {
        PrintErrno(cmd, "unlink() failed, should not, aborting remaining tests", file);
        exit(1);
    }
    return success;
}

bool TestGrowth(const char* cmd, const char* bdev, const char* file, off_t file_size,
                int* test_count) {
    TestCount(test_count);
    bool success = CommandCreate(cmd, bdev, file, file_size, false);
    if (!success) {
        PrintError(cmd, "could not create, allocate, and pin file", file);
        (void)unlink(file);
        return false;
    }

    TestCount(test_count);
    success = CommandEnsure(cmd, bdev, file, false);
    if (!success) {
        PrintError(cmd, "could not verify file", file);
    } else {
        TestCount(test_count);
        if (WriteOneByte(cmd, file, file_size)) {  // if write fails, its not a test error
            if (CommandEnsureExpectingErrors(cmd, bdev, file)) {
                success = false;  // not reliably pinned, ensure should have failed, test failed
            }
        }
    }
    if (unlink(file) < 0) {
        PrintErrno(cmd, "unlink() failed, should not, aborting remaining tests", file);
        exit(1);
    }
    return success;
}

bool TestHole(const char* cmd, const char* bdev, const char* file, off_t file_size, int* test_count,
              bool verify, off_t hole_offset, off_t hole_size) {
    TestCount(test_count);
    bool success = CommandCreate(cmd, bdev, file, file_size, verify);
    if (!success) {
        PrintError(cmd, "could not create, allocate, and pin file", file);
        (void)unlink(file);
        return false;
    }

    TestCount(test_count);
    success = CommandEnsure(cmd, bdev, file, verify);
    if (!success) {
        PrintError(cmd, "could not verify file", file);
    } else {
        TestCount(test_count);
        PunchHoleAndFsync(cmd, file, hole_offset, hole_size);
        success = !CommandEnsureExpectingErrors(cmd, bdev, file);
    }
    if (unlink(file) < 0) {
        PrintErrno(cmd, "unlink() failed, should not, aborting remaining tests", file);
        exit(1);
    }
    return success;
}

bool BoundaryTests(const char* cmd, const char* bdev, const char* file, off_t file_size,
                   bool verify, int* test_count) {
    constexpr off_t block_size = android::f2fs_pin::kF2fsBlockSize;
    constexpr off_t segment_size = android::f2fs_pin::kF2fsSegmentSize;

    // to avoid slowing down tests and excessive writes, only honor verify on this first test
    if (!TestHole(cmd, bdev, file, file_size, test_count, verify, 0, block_size)) {
        PrintError(cmd, "test failed with hole at start of file", file);
        return false;
    }

    if (!TestGrowth(cmd, bdev, file, file_size, test_count)) {
        PrintError(cmd, "test and grow failed", file);
        return false;
    }

    if (!TestHole(cmd, bdev, file, file_size, test_count, false, file_size - block_size,
                  block_size)) {
        PrintError(cmd, "test failed with hole at end of file", file);
        return false;
    }
    if (!TestHole(cmd, bdev, file, file_size, test_count, false, segment_size / 2, block_size)) {
        PrintError(cmd, "test failed with hole at 1/2 segment into file", file);
        return false;
    }
    if (file_size <= segment_size) return true;

    if (!TestHole(cmd, bdev, file, file_size, test_count, false, file_size - segment_size / 2,
                  block_size)) {
        PrintError(cmd, "test failed with hole at 1/2 of last segment of file", file);
        return false;
    }
    if (!TestHole(cmd, bdev, file, file_size, test_count, false, segment_size - block_size,
                  block_size)) {
        PrintError(cmd, "test failed with hole at end of first segment", file);
        return false;
    }
    if (!TestHole(cmd, bdev, file, file_size, test_count, false, segment_size, block_size)) {
        PrintError(cmd, "test failed with hole at start of second segment", file);
        return false;
    }

    if (!TestHole(cmd, bdev, file, file_size, test_count, false, 0, segment_size)) {
        PrintError(cmd, "test failed with whole missing segment at start of file", file);
        return false;
    }
    if (!TestHole(cmd, bdev, file, file_size, test_count, false, segment_size, segment_size)) {
        PrintError(cmd, "test failed with whole missing second segment of file", file);
        return false;
    }
    if (!TestHole(cmd, bdev, file, file_size, test_count, false, file_size - segment_size,
                  segment_size)) {
        PrintError(cmd, "test failed with whole missing last segment of file", file);
        return false;
    }
    if (file_size <= segment_size) return true;

    return true;
}

off_t GetCwdFreeSpace(const char* cmd, const char* dir) {
    struct statfs sfs;
    if (statfs(".", &sfs) < 0) {
        PrintErrno(cmd, "statfs() failed, should not, aborting remaining tests", dir);
        exit(1);
    }
    return sfs.f_bfree * sfs.f_bsize;
}

bool CommandSupport(const char* cmd, const char* bdev) {
    std::string bdev_string(bdev);
    auto result = android::f2fs_pin::BdevFileSystemSupportsReliablePinning(bdev_string);
    if (!result) {
        PrintErrorResult(cmd, "reliable pinning not supported", result);
        return false;
    }
    return true;
}

bool CommandTest(const char* cmd, const char* bdev, const char* dir) {
    if (chdir(dir) < 0) {
        PrintErrno(cmd, "chdir() failed", dir);
        return false;
    }

    struct statfs sfs;
    if (statfs(".", &sfs) < 0) {
        PrintErrno(cmd, "statfs() failed", dir);
        return false;
    }
    if (sfs.f_type != F2FS_SUPER_MAGIC) {
        PrintError(cmd, "stafs() not a F2FS fs", dir);
        return false;
    }
    if (sfs.f_bsize != android::f2fs_pin::kF2fsBlockSize) {
        PrintError(cmd, "stafs() invalid f_bsize", dir);
        return false;
    }

    off_t free_space = GetCwdFreeSpace(cmd, dir);
    if (free_space < 20 * android::f2fs_pin::kF2fsSegmentSize) {
        PrintError(cmd, "need at least 40MB of free space to run tests", dir);
        return false;
    }

    const char* file = "pin_test_file.data";
    bool all_succeeded = true;
    int test_count = 0;

    off_t file_size_too_large_to_verify = 16 * android::f2fs_pin::kF2fsSegmentSize;
    off_t free_space_capped = 2 * file_size_too_large_to_verify;

    if (free_space < free_space_capped) free_space_capped = free_space;

    off_t file_size = android::f2fs_pin::kF2fsSegmentSize;

    // Ensure, imprecisely, that there is enough free space in the file system for the
    // metadata for the file: 4096 is the space needed for the inode, and file_size >> 10
    // is enough space for twice as many disk addresses (4 bytes each) for the 4k blocks
    // required by the file (10 == log2(4k/4))

    while (file_size + 4096 + (file_size >> 10) < free_space_capped) {
        bool verify = file_size < file_size_too_large_to_verify;
        bool success = BoundaryTests(cmd, bdev, file, file_size, verify, &test_count);
        if (!success) {
            std::cerr << cmd << ": test failed\n"
                      << "file_size = " << file_size << "\n"
                      << "verify = " << verify << "\n"
                      << "test_count = " << test_count << "\n\n";
            all_succeeded = false;
            break;
        }
        file_size *= 2;
    }

    // This takes too long on physical devices with lots of free space
    if (all_succeeded) {
        off_t big_file_free_space_capped = 1 << 30;
        if (free_space > big_file_free_space_capped) free_space = big_file_free_space_capped;
        file_size = free_space - 4096 - (free_space >> 10);
        file_size &= ~(android::f2fs_pin::kF2fsSegmentSize - 1);
        bool success = Test(cmd, bdev, file, file_size, &test_count);
        if (!success) {
            std::cerr << cmd << ": test failed\n"
                      << "file_size = " << file_size << "\n"
                      << "verify = 0\n"
                      << "test_count = " << test_count << "\n\n";
            all_succeeded = success;
        }
    }

    if (all_succeeded) std::cout << cmd << ": tests run: " << test_count << "\n";

    return all_succeeded;
}

bool StrToSize(const char* sizestr, off_t* size) {
    char* endptr = nullptr;
    errno = 0;  // to use strtoull(3) errno has to be cleared first
    unsigned long long llsz = strtoull(sizestr, &endptr, 0);

    if (errno || endptr == sizestr || !endptr || llsz > INT64_MAX) return false;

    if (*endptr) {
        if (endptr[1]) return false;
        unsigned int shift;
        switch (*endptr) {
            default:
                return false;
            case 'k':
                shift = 10;
                break;
            case 'm':
                shift = 20;
                break;
            case 'g':
                shift = 30;
                break;
            case 't':
                shift = 40;
                break;
        }
        if (llsz > (INT64_MAX >> shift)) return false;
        llsz <<= shift;
    }

    *size = off_t(llsz);
    return true;
}

void UsageAndExit(const char* cmd) {
    std::cerr << "\n"
                 "usage: "
              << cmd
              << " --create bdev file size\n"
                 "usage: "
              << cmd
              << " --create-init bdev file size\n"
                 "usage: "
              << cmd
              << " --ensure bdev file\n"
                 "usage: "
              << cmd
              << " --verify bdev file\n"
                 "usage: "
              << cmd
              << " --support bdev\n"
                 "usage: "
              << cmd
              << " --tests bdev dir\n"
                 "\n"
                 "  --create bdev file size\n"
                 "\n"
                 "    Create file of size bytes, size must be a multiple of 2MB, and pin it.\n"
                 "\n"
                 "    The size in decimal, hex or octal; units of k, m and g (KiB, MiB,\n"
                 "    and GiB respectively) can be appended to it, e.g.: 64m, 0x1000, 0177k.\n"
                 "\n"
                 "  --create-init bdev file size\n"
                 "\n"
                 "    Same as --create, also initialize file to a pattern for validation and\n"
                 "    validate its extent map and contents through bdev.\n"
                 "\n"
                 "  --ensure bdev file\n"
                 "\n"
                 "    If file is not reliably pinned produce an error.\n"
                 "\n"
                 "  --verify bdev file\n"
                 "\n"
                 "    Same as --ensure, also verify data of file initialized with --create-init\n"
                 "\n"
                 "  --support bdev\n"
                 "\n"
                 "    Determine if bdev supports reliable pinning\n"
                 "\n"
                 "  --test bdev dir\n"
                 "\n"
                 "    Run various tests creating files inside dir, dir must exist,\n"
                 "    dir should be a directory on an F2FS filesystem on bdev.\n"
                 "    If the tests are succesful all temporary files are removed.\n"
                 "\n";

    exit(1);
}

char* CommandName(char* c) {
    char* p = strrchr(c, '/');
    return p ? p + 1 : c;
}

int main(int argc, char* argv[]) {
    const char* cmd = CommandName(argv[0]);
    bool success = false;

    if (argc == 5) {
        bool init_file = false;
        if (strcmp(argv[1], "--create") == 0)
            init_file = false;
        else if (strcmp(argv[1], "--create-init") == 0)
            init_file = true;
        else
            UsageAndExit(cmd);
        off_t file_size = 0;
        if (!StrToSize(argv[4], &file_size)) {
            PrintError(cmd, "invalid file size value", argv[4]);
            UsageAndExit(cmd);
        }
        success = CommandCreate(cmd, argv[2], argv[3], file_size, init_file);
    } else if (argc == 4) {
        if (strcmp(argv[1], "--test") == 0) {
            success = CommandTest(cmd, argv[2], argv[3]);
        } else {
            bool verify_file = false;
            if (strcmp(argv[1], "--ensure") == 0)
                verify_file = false;
            else if (strcmp(argv[1], "--verify") == 0)
                verify_file = true;
            else
                UsageAndExit(cmd);
            success = CommandEnsure(cmd, argv[2], argv[3], verify_file);
        }
    } else if (argc == 3) {
        if (strcmp(argv[1], "--support") == 0) {
            success = CommandSupport(cmd, argv[2]);
        } else {
            UsageAndExit(cmd);
        }
    } else {
        UsageAndExit(cmd);
    }
    if (!success) exit(1);
    exit(0);
}
