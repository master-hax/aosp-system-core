/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <errno.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <memory>

#ifndef F2FS_IOCTL_MAGIC
#define F2FS_IOCTL_MAGIC 0xf5
#define F2FS_IOC_SET_PIN_FILE _IOW(F2FS_IOCTL_MAGIC, 13, __u32)
#define F2FS_IOC_GET_PIN_FILE _IOR(F2FS_IOCTL_MAGIC, 14, __u32)
#endif

namespace android::f2fs_pin {

constexpr uint32_t kEntangledDataExtentFlags =
        FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC | FIEMAP_EXTENT_ENCODED |
        FIEMAP_EXTENT_DATA_ENCRYPTED | FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_DATA_INLINE |
        FIEMAP_EXTENT_DATA_TAIL | FIEMAP_EXTENT_UNWRITTEN | FIEMAP_EXTENT_MERGED |
        FIEMAP_EXTENT_SHARED;

constexpr uint32_t kAllFiemapExtentFlags = FIEMAP_EXTENT_LAST | kEntangledDataExtentFlags;

//  The Linux 32 bit ABI is botched in that it presents a device number as a 32 bit number.
//  The 64 bit ABI presents them as 64 bit numbers. The statx(2) system call exposes the major
//  and minor numbers as two unsigned 32 bit numbers. This code used to use statx(2) so that
//  truncated device numbers are not the source of some very unlikely confusion on part of the
//  API caller that could lead to some very unlikely data corruption. The statx(2) system call
//  was introduced in Linux 4.11, and it is not yet exposed in Android's bionic C library.

// #define USE_STATX
#ifdef USE_STATX

struct DeviceNumber {
    uint32_t major;
    uint32_t minor;
    bool Equals(DeviceNumber& that) { return major == that.major && minor == that.minor; }
};

#else

struct DeviceNumber {
    dev_t devno;
    bool Equals(DeviceNumber& that) { return devno == that.devno; }
};

#endif

static Result FileGetSize(int file_fd, off_t* file_size) {
    struct stat st;
    if (fstat(file_fd, &st) < 0) {
        *file_size = 0;
        return android::base::ErrnoErrorf("fstat() failed");
    }
    *file_size = st.st_size;
    return {};
}

#ifdef USE_STATX

static Result FileGetFileSystemDeviceNumber(int file_fd, DeviceNumber* device_number) {
    device_number->major = 0;
    device_number->minor = 0;
    struct statx stx;
    if (statx(file_fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) < 0)
        return android::base::ErrnoErrorf("statx() failed");

    if ((stx.stx_mode & S_IFMT) != S_IFREG)
        return android::base::Errorf(("file_fd not a regular device");

    device_number->major = stx.stx_dev_major;
    device_number->minor = stx.stx_dev_minor;
    return {};
}

static Result BdevGetDeviceNumber(int bdev_fd, DeviceNumber* device_number) {
    device_number->major = 0;
    device_number->minor = 0;
    struct statx stx;

    if (statx(bdev_fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) < 0)
        return android::base::ErrnoErrorf("statx() failed");

    if ((stx.stx_mode & S_IFMT) != S_IFBLK)
        return android::base::Errorf("bdev_fd not a block device");

    device_number->major = stx.stx_rdev_major;
    device_number->minor = stx.stx_rdev_minor;
    return {};
}

static Result BdevNameGetDeviceNumber(const std::string& bdev_name, DeviceNumber* device_number) {
    device_number->major = 0;
    device_number->minor = 0;
    struct statx stx;

    if (statx(-1, bdev_name.c_str(), 0, STATX_BASIC_STATS, &stx) < 0)
        return android::base::ErrnoErrorf("statx() failed");

    if ((stx.stx_mode & S_IFMT) != S_IFBLK)
        return android::base::Errorf("bdev_name not a block device");

    device_number->major = stx.stx_rdev_major;
    device_number->minor = stx.stx_rdev_minor;
    return {};
}

#else

static Result FileGetFileSystemDeviceNumber(int file_fd, DeviceNumber* device_number) {
    device_number->devno = 0;
    struct stat st;
    if (fstat(file_fd, &st) < 0) return android::base::ErrnoErrorf("stat() failed");

    if ((st.st_mode & S_IFMT) != S_IFREG)
        return android::base::Errorf("file_fd not a regular device");

    device_number->devno = st.st_dev;
    return {};
}

static Result BdevGetDeviceNumber(int bdev_fd, DeviceNumber* device_number) {
    device_number->devno = 0;
    struct stat st;

    if (fstat(bdev_fd, &st) < 0) return android::base::ErrnoErrorf("stat() failed");

    if ((st.st_mode & S_IFMT) != S_IFBLK)
        return android::base::Errorf("bdev_fd not a block device");

    device_number->devno = st.st_rdev;
    return {};
}

static Result BdevNameGetDeviceNumber(const std::string& bdev_name, DeviceNumber* device_number) {
    device_number->devno = 0;
    struct stat st;

    if (stat(bdev_name.c_str(), &st) < 0) return android::base::ErrnoErrorf("fstat() failed");

    if ((st.st_mode & S_IFMT) != S_IFBLK)
        return android::base::Errorf("bdev_name not a block device");

    device_number->devno = st.st_rdev;
    return {};
}

#endif

static Result FileOnFileSystemOnBdev(int file_fd, int bdev_fd) {
    DeviceNumber file_system_device_number;
    Result result = FileGetFileSystemDeviceNumber(file_fd, &file_system_device_number);
    if (!result) return result;

    DeviceNumber bdev_device_number;
    result = BdevGetDeviceNumber(bdev_fd, &bdev_device_number);
    if (!result) return result;

    if (!bdev_device_number.Equals(file_system_device_number))
        return android::base::Errorf("file_fd not on file system on bdev_fd");

    return {};
}

static Result BdevNameDeviceNumberSameAsBdev(const std::string& bdev_name, int bdev_fd) {
    DeviceNumber bdev_device_number;
    Result result = BdevGetDeviceNumber(bdev_fd, &bdev_device_number);
    if (!result) return result;

    DeviceNumber bdev_name_device_number;
    result = BdevNameGetDeviceNumber(bdev_name, &bdev_name_device_number);
    if (!result) return result;

    if (!bdev_device_number.Equals(bdev_name_device_number))
        return android::base::Errorf("device numbers different between bdev_name and bdev_fd");

    return {};
}

static Result BdevGetMainBlkaddrOffset(const std::string& bdev_name, off_t* main_blkaddr_offset) {
    char buf[128];
    *main_blkaddr_offset = 0;

    std::string::size_type index = bdev_name.rfind('/');
    std::string::size_type length = bdev_name.length();
    if (length == 0 || bdev_name[0] != '/' || index == std::string::npos || index + 1 == length)
        return android::base::Errorf("bdev_name is not absolute");

    std::string main_blkaddr_file = "/sys/fs/f2fs" + bdev_name.substr(index) + "/main_blkaddr";

    android::base::unique_fd fd(open(main_blkaddr_file.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd < 0)
        return android::base::ErrnoErrorf("main_blkaddr open() for bdev in /sys/fs/f2fs failed");
    ssize_t nread = read(fd, buf, sizeof(buf) - 1);

    if (nread < 0) return android::base::ErrnoErrorf("read() failed");

    buf[nread] = 0;
    errno = 0;  // to use strtoull(3) errno has to be cleared first
    unsigned long long llsz = strtoull(buf, nullptr, 0);
    if (errno) return android::base::ErrnoErrorf("invalid /sys/fs/f2fs main_blkaddr value");

    *main_blkaddr_offset = llsz * kF2fsBlockSize;
    return {};
}

static Result BdevHasPinFileFeature(const std::string& bdev_name) {
    std::string::size_type index = bdev_name.rfind('/');
    std::string::size_type length = bdev_name.length();
    if (length == 0 || bdev_name[0] != '/' || index == std::string::npos || index + 1 == length)
        return android::base::Errorf("bdev_name is not absolute");

    std::string features_file = "/sys/fs/f2fs" + bdev_name.substr(index) + "/features";

    android::base::unique_fd fd(open(features_file.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd < 0)
        return android::base::ErrnoErrorf("features open() for bdev in /sys/fs/f2fs failed");

    off_t file_size = 0;
    auto result = FileGetSize(fd, &file_size);
    if (!result) return result;

    if (file_size > 1024 * 1024)
        return android::base::Errorf("size of features for bdev in /sys/fs/f2fs is too large");

    char* bp = new char[file_size + 1];
    if (bp == NULL) android::base::Errorf("could not allocate buffer to read f2fs bdev features");

    auto buf = std::unique_ptr<char[]>(bp);
    ssize_t nread = read(fd, bp, (size_t)file_size);

    if (nread < 0) return android::base::ErrnoErrorf("read() failed");
    if (nread < file_size) {
        //  sysfs or f2fs in Linux is buggy, stat(2) reports file size of 4096, even if the data
        //  that can be read is less, work around that, note that partial reads should not occur,
        //  this is not a device returning arbitrary input as it arrives

        switch (read(fd, bp + nread, (size_t)(file_size - nread))) {
            case 0:
                break;
            case -1:
                return android::base::ErrnoErrorf("second read reading f2fs bdev features failed");
            default:
                return android::base::Errorf("partial read reading f2fs bdev features");
        }
        file_size = nread;
    }
    bp[file_size] = 0;

    char* savedptr = NULL;
    char* tok;
    while ((tok = strtok_r(bp, ", \n", &savedptr)) != NULL) {
        bp = NULL;  // should only be non-NULL on first call to strtok_r(3)
        if (strcmp(tok, "pin_file") == 0) return {};
    }

    return android::base::Errorf("pin_file feature not supported by bdev");
}

static Result FileOnF2fsFileSystem(int file_fd) {
    struct statfs sfs;
    if (fstatfs(file_fd, &sfs) < 0) return android::base::ErrnoErrorf("fstafs() failed");

    if (sfs.f_type != F2FS_SUPER_MAGIC) return android::base::Errorf("fstafs() not a F2FS fs");

    if (sfs.f_bsize != kF2fsBlockSize) return android::base::Errorf("fstafs() invalid f_bsize");

    return {};
}

static Result ValidateFileAndBdev(int file_fd, int bdev_fd, const std::string& bdev_name,
                                  off_t* main_blkaddr_offset) {
    Result result = FileOnFileSystemOnBdev(file_fd, bdev_fd);
    if (!result) return result;

    result = BdevNameDeviceNumberSameAsBdev(bdev_name, bdev_fd);
    if (!result) return result;

    result = FileOnF2fsFileSystem(file_fd);
    if (!result) return result;

    result = BdevHasPinFileFeature(bdev_name);
    if (!result) return result;

    result = BdevGetMainBlkaddrOffset(bdev_name, main_blkaddr_offset);
    if (!result) return result;

    return {};
}

static Result FilePin(int file_fd) {
    uint32_t set = 1;
    if (ioctl(file_fd, F2FS_IOC_SET_PIN_FILE, &set) < 0)
        return android::base::ErrnoErrorf("ioctl() to pin file failed");

    return {};
}

static Result FileEnsureItsPinned(int file_fd) {
    uint32_t flags = 0;
    if (ioctl(file_fd, FS_IOC_GETFLAGS, &flags) < 0)
        return android::base::ErrnoErrorf("ioctl() F2FS_IOC_GETFLAGS");

    if (!(flags & FS_NOCOW_FL))
        return android::base::Errorf("expected file to be pinned, it is not pinned");

    return {};
}

static Result FileAllocateAndFsync(int file_fd, off_t size) {
    if (fallocate(file_fd, 0, (off_t)0, size) < 0)
        return android::base::ErrnoErrorf("fallocate() failed");

    if (fsync(file_fd) < 0) return android::base::ErrnoErrorf("fsync() failed");

    return {};
}

static Result FileTruncateAndFsync(int file_fd) {
    if (ftruncate(file_fd, (off_t)0) < 0) return android::base::ErrnoErrorf("ftruncate() failed");

    if (fsync(file_fd) < 0) return android::base::ErrnoErrorf("fsync() failed");

    return {};
}

// Get the first extent within [offset, offset + length), if no error, then
// em->em_fiemap.fm_extents contains the extent information.

Result FileGetExtentMap(int file_fd, off_t offset, off_t length, ExtentMap* em) {
    em->em_fiemap.fm_start = uint64_t(offset);
    em->em_fiemap.fm_length = uint64_t(length);
    em->em_fiemap.fm_flags = 0;
    em->em_fiemap.fm_mapped_extents = 0;
    em->em_fiemap.fm_extent_count = 1;

    if (ioctl(file_fd, FS_IOC_FIEMAP, &em->em_fiemap) < 0)
        return android::base::ErrnoErrorf("ioctl() FS_IOC_FIEMAP failed");
    return {};
}

Result FiemapExtentValidate(FiemapExtent* fe) {
    if (fe->fe_logical > INT64_MAX || fe->fe_physical > INT64_MAX || fe->fe_length > INT64_MAX ||
        fe->fe_length == 0)
        return android::base::Errorf("invalid extent");

    if (fe->fe_flags & kEntangledDataExtentFlags)
        return android::base::Errorf("extent flags improper for direct I/O from device");

    if (fe->fe_flags & ~kAllFiemapExtentFlags) return android::base::Errorf("unknown extent flags");

    return {};
}

static Result FileVerifyItsReliablyPinned(int file_fd, off_t main_blkaddr_offset) {
    Result result = FileEnsureItsPinned(file_fd);
    if (!result) return result;

    uint32_t attempts = 0;
    if (ioctl(file_fd, F2FS_IOC_GET_PIN_FILE, &attempts) < 0)
        return android::base::ErrnoErrorf("ioctl() get internal F2FS file unpinning choice failed");

    if (attempts != 0) return android::base::Errorf("F2FS will eventually unpin this file");

    off_t file_size;
    result = FileGetSize(file_fd, &file_size);
    if (!result) return result;

    if (file_size % kF2fsSegmentSize)
        return android::base::Errorf("file size is not a multiple of 2MB");

    ExtentMap em;
    FiemapExtent* fe = em.em_fiemap.fm_extents;

    for (off_t offset = 0; offset < file_size;) {
        off_t leftover = file_size - offset;
        result = FileGetExtentMap(file_fd, offset, leftover, &em);
        if (!result) return result;

        result = FiemapExtentValidate(fe);
        if (!result) return result;

        if (fe->fe_logical != offset) return android::base::Errorf("file should not have holes");

        if (fe->fe_length > leftover)
            return android::base::Errorf("file should not have storage past end of file");

        if (fe->fe_physical < main_blkaddr_offset)
            return android::base::Errorf("file storage should not be prior to main_blkaddr");

        if ((fe->fe_physical - main_blkaddr_offset) % kF2fsSegmentSize)
            return android::base::Errorf("extent is not 2MB aligned with respect to main_blkaddr");

        if (fe->fe_length % kF2fsSegmentSize)
            return android::base::Errorf("extent space is not multiple of 2MB");

        offset += fe->fe_length;
        leftover -= fe->fe_length;
    }

    return {};
}

Result BdevFileSystemSupportsReliablePinning(const std::string& bdev_name) {
    Result result = BdevHasPinFileFeature(bdev_name);
    if (!result) return result;

    off_t main_blkaddr_offset;
    return BdevGetMainBlkaddrOffset(bdev_name, &main_blkaddr_offset);
}

Result FileAllocateSpaceAndReliablyPin(int file_fd, int bdev_fd, const std::string& bdev_name,
                                       off_t size) {
    off_t main_blkaddr_offset;
    Result result = ValidateFileAndBdev(file_fd, bdev_fd, bdev_name, &main_blkaddr_offset);
    if (!result) return result;

    if (size % kF2fsSegmentSize) return android::base::Errorf("size not a multiple of 2MB");

    off_t file_size;
    result = FileGetSize(file_fd, &file_size);
    if (!result) return result;

    if (file_size != 0) return android::base::Errorf("file size is not zero");

    result = FilePin(file_fd);
    if (!result) return result;

    if (!(result = FileAllocateAndFsync(file_fd, size)) ||
        !(result = FileVerifyItsReliablyPinned(file_fd, main_blkaddr_offset))) {
        (void)FileTruncateAndFsync(file_fd);
        return result;
    }

    return {};
}

Result FileEnsureReliablyPinned(int file_fd, int bdev_fd, const std::string& bdev_name) {
    off_t main_blkaddr_offset;
    Result result = ValidateFileAndBdev(file_fd, bdev_fd, bdev_name, &main_blkaddr_offset);
    if (!result) return result;

    if (fsync(file_fd) < 0) return android::base::ErrnoErrorf("fsync() failed");

    return FileVerifyItsReliablyPinned(file_fd, main_blkaddr_offset);
}

}  // namespace android::f2fs_pin
