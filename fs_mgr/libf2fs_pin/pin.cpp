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

class DeviceNumber {
  public:
    DeviceNumber(uint32_t maj, uint32_t min) : major(maj), min(min) {}
    bool Equals(DeviceNumber& that) { return major == that.major && minor == that.minor; }

  private:
    uint32_t major;
    uint32_t minor;
};

#else

class DeviceNumber {
  public:
    DeviceNumber(dev_t dev) : devno(dev) {}
    bool Equals(DeviceNumber& that) { return devno == that.devno; }

  private:
    dev_t devno;
};

#endif

//  Use of the android::base::Result<> template renders the code more inescrutable in so far as
//  what would have been output arguments with mnemonic names are now subsumed in the pseudo tuple
//  Result returning mechanism of the Result template, the tuple element value accessor: value()
//  conveys no meaning to the person that reads the code about what is being returned.  Because
//  of that these types are used to attempt to convery that meaning.

typedef android::base::Result<off_t> ResultFileSize;
typedef android::base::Result<off_t> ResultMainBlkaddrOffset;
typedef android::base::Result<DeviceNumber> ResultDeviceNumber;

static ResultFileSize FileGetSize(int file_fd) {
    struct stat st;
    if (fstat(file_fd, &st) < 0) return android::base::ErrnoErrorf("fstat() failed");

    return st.st_size;
}

#ifdef USE_STATX

static ResultDeviceNumber FileGetFileSystemDeviceNumber(int file_fd) {
    struct statx stx;
    if (statx(file_fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) < 0)
        return android::base::ErrnoErrorf("statx() failed");

    if ((stx.stx_mode & S_IFMT) != S_IFREG)
        return android::base::Errorf("file_fd not a regular device");

    return DeviceNumber(stx.stx.stx_dev_major, stx.stx_dev_minor);
}

static ResultDeviceNumber BdevGetDeviceNumber(int bdev_fd) {
    struct statx stx;
    if (statx(bdev_fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) < 0)
        return android::base::ErrnoErrorf("statx() failed");

    if ((stx.stx_mode & S_IFMT) != S_IFBLK)
        return android::base::Errorf("bdev_fd not a block device");

    return DeviceNumber(stx.stx_rdev_major; stx.stx_rdev_minor);
}

static ResultDeviceNumber BdevNameGetDeviceNumber(const std::string& bdev_name) {
    struct statx stx;
    if (statx(-1, bdev_name.c_str(), 0, STATX_BASIC_STATS, &stx) < 0)
        return android::base::ErrnoErrorf("statx() failed: {}", bdev_name);

    if ((stx.stx_mode & S_IFMT) != S_IFBLK)
        return android::base::Errorf("bdev_name not a block device: {}", bdev_name);

    return DeviceNumber(stx.stx_rdev_major, stx.stx_rdev_minor);
}

#else

static ResultDeviceNumber FileGetFileSystemDeviceNumber(int file_fd) {
    struct stat st;
    if (fstat(file_fd, &st) < 0) return android::base::ErrnoErrorf("stat() failed");

    if ((st.st_mode & S_IFMT) != S_IFREG)
        return android::base::Errorf("file_fd not a regular device");

    return DeviceNumber(st.st_dev);
}

static ResultDeviceNumber BdevGetDeviceNumber(int bdev_fd) {
    struct stat st;
    if (fstat(bdev_fd, &st) < 0) return android::base::ErrnoErrorf("stat() failed");

    if ((st.st_mode & S_IFMT) != S_IFBLK)
        return android::base::Errorf("bdev_fd not a block device");

    return DeviceNumber(st.st_rdev);
}

static ResultDeviceNumber BdevNameGetDeviceNumber(const std::string& bdev_name) {
    struct stat st;
    if (stat(bdev_name.c_str(), &st) < 0)
        return android::base::ErrnoErrorf("fstat() failed: {}", bdev_name);

    if ((st.st_mode & S_IFMT) != S_IFBLK)
        return android::base::Errorf("bdev_name not a block device: {}", bdev_name);

    return DeviceNumber(st.st_rdev);
}

#endif

static Result FileOnFileSystemOnBdev(int file_fd, int bdev_fd) {
    auto result_device_number = FileGetFileSystemDeviceNumber(file_fd);
    if (!result_device_number) return result_device_number.error();
    DeviceNumber file_system_device_number(result_device_number.value());

    result_device_number = BdevGetDeviceNumber(bdev_fd);
    if (!result_device_number) return result_device_number.error();
    DeviceNumber bdev_device_number(result_device_number.value());

    if (!bdev_device_number.Equals(file_system_device_number))
        return android::base::Errorf("file_fd not on file system on bdev_fd");

    return {};
}

static Result BdevNameDeviceNumberSameAsBdev(const std::string& bdev_name, int bdev_fd) {
    auto result_device_number = BdevGetDeviceNumber(bdev_fd);
    if (!result_device_number) return result_device_number.error();
    DeviceNumber bdev_device_number(result_device_number.value());

    result_device_number = BdevNameGetDeviceNumber(bdev_name);
    if (!result_device_number) return result_device_number.error();
    DeviceNumber bdev_name_device_number(result_device_number.value());

    if (!bdev_device_number.Equals(bdev_name_device_number))
        return android::base::Errorf("device numbers different between bdev_name and bdev_fd: {}",
                                     bdev_name);

    return {};
}

static ResultMainBlkaddrOffset BdevGetMainBlkaddrOffset(const std::string& bdev_name) {
    char buf[128];

    std::string::size_type index = bdev_name.rfind('/');
    std::string::size_type length = bdev_name.length();
    if (length == 0 || bdev_name[0] != '/' || index == std::string::npos || index + 1 == length)
        return android::base::Errorf("bdev_name is not absolute: {}", bdev_name);

    std::string main_blkaddr_file = "/sys/fs/f2fs" + bdev_name.substr(index) + "/main_blkaddr";

    android::base::unique_fd fd(open(main_blkaddr_file.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd < 0) return android::base::ErrnoErrorf("open() failed: {}", main_blkaddr_file);
    ssize_t nread = read(fd, buf, sizeof(buf) - 1);

    if (nread < 0) return android::base::ErrnoErrorf("read() failed");

    buf[nread] = 0;
    errno = 0;  // to use strtoull(3) errno has to be cleared first
    unsigned long long llsz = strtoull(buf, nullptr, 0);
    if (errno) return android::base::ErrnoErrorf("invalid main_blkaddr: {}", main_blkaddr_file);

    return off_t(llsz * kF2fsBlockSize);
}

static Result BdevHasPinFileFeature(const std::string& bdev_name) {
    std::string::size_type index = bdev_name.rfind('/');
    std::string::size_type length = bdev_name.length();
    if (length == 0 || bdev_name[0] != '/' || index == std::string::npos || index + 1 == length)
        return android::base::Errorf("bdev_name is not absolute: {}", bdev_name);

    std::string features_file = "/sys/fs/f2fs" + bdev_name.substr(index) + "/features";

    android::base::unique_fd fd(open(features_file.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd < 0) return android::base::ErrnoErrorf("open() failed: {}", features_file);

    auto result_file_size = FileGetSize(fd);
    if (!result_file_size) return result_file_size.error();

    off_t file_size = result_file_size.value();
    if (file_size > 1024 * 1024)
        return android::base::Errorf("size of features file is too large: {}", features_file);

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

static ResultMainBlkaddrOffset ValidateAndGetMainBlkaddrOffset(int file_fd, int bdev_fd,
                                                               const std::string& bdev_name) {
    Result result = FileOnFileSystemOnBdev(file_fd, bdev_fd);
    if (!result) return result.error();

    result = BdevNameDeviceNumberSameAsBdev(bdev_name, bdev_fd);
    if (!result) return result.error();

    result = FileOnF2fsFileSystem(file_fd);
    if (!result) return result.error();

    result = BdevHasPinFileFeature(bdev_name);
    if (!result) return result.error();

    auto result_main_blkaddr_offset = BdevGetMainBlkaddrOffset(bdev_name);
    if (!result_main_blkaddr_offset) return result_main_blkaddr_offset.error();

    return result_main_blkaddr_offset;
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

//  Get the first extent within [offset, offset + length), if no error, then
//  em->em_fiemap.fm_extents contains the extent information.

ResultExtentMap FileGetExtentMap(int file_fd, off_t offset, off_t length) {
    ExtentMap em;
    em.em_fiemap.fm_start = uint64_t(offset);
    em.em_fiemap.fm_length = uint64_t(length);
    em.em_fiemap.fm_flags = 0;
    em.em_fiemap.fm_mapped_extents = 0;
    em.em_fiemap.fm_extent_count = 1;
    if (ioctl(file_fd, FS_IOC_FIEMAP, &em.em_fiemap) < 0)
        return android::base::ErrnoErrorf("ioctl() FS_IOC_FIEMAP failed");

    return em;
}

Result FiemapExtentValidate(const FiemapExtent& fe) {
    if (fe.fe_logical > INT64_MAX || fe.fe_physical > INT64_MAX || fe.fe_length > INT64_MAX ||
        fe.fe_length == 0)
        return android::base::Errorf("invalid extent");

    if (fe.fe_flags & kEntangledDataExtentFlags)
        return android::base::Errorf("extent flags improper for direct I/O from device");

    if (fe.fe_flags & ~kAllFiemapExtentFlags) return android::base::Errorf("unknown extent flags");

    return {};
}

static Result FileVerifyItsReliablyPinned(int file_fd, off_t main_blkaddr_offset) {
    Result result = FileEnsureItsPinned(file_fd);
    if (!result) return result;

    uint32_t attempts = 0;
    if (ioctl(file_fd, F2FS_IOC_GET_PIN_FILE, &attempts) < 0)
        return android::base::ErrnoErrorf("ioctl() get internal F2FS file unpinning choice failed");

    if (attempts != 0) return android::base::Errorf("F2FS will eventually unpin this file");

    auto result_file_size = FileGetSize(file_fd);
    if (!result_file_size) return result_file_size.error();

    off_t file_size = result_file_size.value();
    if (file_size % kF2fsSegmentSize)
        return android::base::Errorf("file size is not a multiple of 2MB");

    for (off_t offset = 0; offset < file_size;) {
        off_t leftover = file_size - offset;
        auto result_extent_map = FileGetExtentMap(file_fd, offset, leftover);
        if (!result_extent_map) return result_extent_map.error();
        ExtentMap em = result_extent_map.value();
        FiemapExtent* fe = em.em_fiemap.fm_extents;

        result = FiemapExtentValidate(*fe);
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

    auto result_main_blkaddr_offset = BdevGetMainBlkaddrOffset(bdev_name);
    if (!result_main_blkaddr_offset) return result_main_blkaddr_offset.error();

    return {};
}

Result FileAllocateSpaceAndReliablyPin(int file_fd, int bdev_fd, const std::string& bdev_name,
                                       off_t size) {
    auto result_main_blkaddr_offset = ValidateAndGetMainBlkaddrOffset(file_fd, bdev_fd, bdev_name);
    if (!result_main_blkaddr_offset) return result_main_blkaddr_offset.error();
    off_t main_blkaddr_offset = result_main_blkaddr_offset.value();

    if (size % kF2fsSegmentSize) return android::base::Errorf("size not a multiple of 2MB");

    auto result_file_size = FileGetSize(file_fd);
    if (!result_file_size) return result_file_size.error();

    off_t file_size = result_file_size.value();
    if (file_size != 0) return android::base::Errorf("file size is not zero");

    auto result = FilePin(file_fd);
    if (!result) return result;

    if (!(result = FileAllocateAndFsync(file_fd, size)) ||
        !(result = FileVerifyItsReliablyPinned(file_fd, main_blkaddr_offset))) {
        (void)FileTruncateAndFsync(file_fd);
        return result;
    }

    return {};
}

Result FileEnsureReliablyPinned(int file_fd, int bdev_fd, const std::string& bdev_name) {
    auto result_main_blkaddr_offset = ValidateAndGetMainBlkaddrOffset(file_fd, bdev_fd, bdev_name);
    if (!result_main_blkaddr_offset) return result_main_blkaddr_offset.error();
    off_t main_blkaddr_offset = result_main_blkaddr_offset.value();

    if (fsync(file_fd) < 0) return android::base::ErrnoErrorf("fsync() failed: {}", bdev_name);

    return FileVerifyItsReliablyPinned(file_fd, main_blkaddr_offset);
}

}  // namespace android::f2fs_pin
