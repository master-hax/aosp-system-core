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

#include "libpin/pin.h"
#include "pin_impl.h"

#include <errno.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/stat.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#ifndef F2FS_IOCTL_MAGIC
#define F2FS_IOCTL_MAGIC 0xf5
#define F2FS_IOC_SET_PIN_FILE _IOW(F2FS_IOCTL_MAGIC, 13, __u32)
#define F2FS_IOC_GET_PIN_FILE _IOR(F2FS_IOCTL_MAGIC, 14, __u32)
#endif

namespace android::pin {

//  A Result value has an internal pointer to a statically allocated ResultValues object.

class ResultValues {
  private:
    const char* description_;
    const char* function_;
    const char* scope_;
    const char* file_;
    int line_;

  public:
    ResultValues(const char* file, const char* scope, const char* function, int line,
                 const char* description) {
        description_ = description;
        function_ = function;
        scope_ = scope;
        file_ = file;
        line_ = line;
    }
    const char* GetDescription() const { return description_; }
    const char* GetFunction() const { return function_; }
    const char* GetScope() const { return scope_; }
    const char* GetFile() const { return file_; }
    int GetLine() const { return line_; }
};

//  Non IsError() result values have their values_ pointer point to result_values_no_error.

ResultValues result_values_no_error("Result::GetFile() called when IsError() is false",
                                    "Result::GetScope() called when IsError() is false",
                                    "Result::GetFunction() called when IsError() is false", 0,
                                    "Result::GetDescription() called when IsError() is false");

//  A single instance of the value of __FILE__ is shared by all the ResultValues.

static const char* source_file_name = {__FILE__};

//  Statement macro to make code that results Result values cleaner to write.

#define return_Result(desc) return_ResultErrno(desc, 0)

//  Statement macro to make code that results Result values with an errno cleaner to write.

#define return_ResultErrno(desc, error)                                                            \
    do {                                                                                           \
        static ResultValues rvals(source_file_name, "android::pin", __FUNCTION__, __LINE__, desc); \
        return Result(&rvals, error);                                                              \
    } while (0)

//  Implementation of the Result member functions.

const char* Result::GetDescription() {
    return values_->GetDescription();
}
const char* Result::GetFunction() {
    return values_->GetFunction();
}
const char* Result::GetScope() {
    return values_->GetScope();
}
const char* Result::GetFile() {
    return values_->GetFile();
}
int Result::GetLine() {
    return values_->GetLine();
}

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
        return_ResultErrno("fstat() failed", errno);
    }
    *file_size = st.st_size;
    return Result();
}

#ifdef USE_STATX

static Result FileGetFileSystemDeviceNumber(int file_fd, DeviceNumber* device_number) {
    device_number->major = 0;
    device_number->minor = 0;
    struct statx stx;
    if (statx(file_fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) < 0)
        return_ResultErrno("statx() failed", errno);

    if ((stx.stx_mode & S_IFMT) != S_IFREG) return_Result("file_fd not a regular device");

    device_number->major = stx.stx_dev_major;
    device_number->minor = stx.stx_dev_minor;
    return Result();
}

static Result BdevGetDeviceNumber(int bdev_fd, DeviceNumber* device_number) {
    device_number->major = 0;
    device_number->minor = 0;
    struct statx stx;

    if (statx(bdev_fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) < 0)
        return_ResultErrno("statx() failed", errno);

    if ((stx.stx_mode & S_IFMT) != S_IFBLK) return_Result("bdev_fd not a block device");

    device_number->major = stx.stx_rdev_major;
    device_number->minor = stx.stx_rdev_minor;
    return Result();
}

static Result BdevNameGetDeviceNumber(std::string bdev_name, DeviceNumber* device_number) {
    device_number->major = 0;
    device_number->minor = 0;
    struct statx stx;

    if (statx(-1, bdev_name.c_str(), 0, STATX_BASIC_STATS, &stx) < 0)
        return_ResultErrno("statx() failed", errno);

    if ((stx.stx_mode & S_IFMT) != S_IFBLK) return_Result("bdev_name not a block device");

    device_number->major = stx.stx_rdev_major;
    device_number->minor = stx.stx_rdev_minor;
    return Result();
}

#else

static Result FileGetFileSystemDeviceNumber(int file_fd, DeviceNumber* device_number) {
    device_number->devno = 0;
    struct stat st;
    if (fstat(file_fd, &st) < 0) return_ResultErrno("stat() failed", errno);

    if ((st.st_mode & S_IFMT) != S_IFREG) return_Result("file_fd not a regular device");

    device_number->devno = st.st_dev;
    return Result();
}

static Result BdevGetDeviceNumber(int bdev_fd, DeviceNumber* device_number) {
    device_number->devno = 0;
    struct stat st;

    if (fstat(bdev_fd, &st) < 0) return_ResultErrno("stat() failed", errno);

    if ((st.st_mode & S_IFMT) != S_IFBLK) return_Result("bdev_fd not a block device");

    device_number->devno = st.st_rdev;
    return Result();
}

static Result BdevNameGetDeviceNumber(std::string bdev_name, DeviceNumber* device_number) {
    device_number->devno = 0;
    struct stat st;

    if (stat(bdev_name.c_str(), &st) < 0) return_ResultErrno("fstat() failed", errno);

    if ((st.st_mode & S_IFMT) != S_IFBLK) return_Result("bdev_name not a block device");

    device_number->devno = st.st_rdev;
    return Result();
}

#endif

static Result FileOnFileSystemOnBdev(int file_fd, int bdev_fd) {
    DeviceNumber file_system_device_number;
    Result result = FileGetFileSystemDeviceNumber(file_fd, &file_system_device_number);
    if (result.IsError()) return result;

    DeviceNumber bdev_device_number;
    result = BdevGetDeviceNumber(bdev_fd, &bdev_device_number);
    if (result.IsError()) return result;

    if (!bdev_device_number.Equals(file_system_device_number))
        return_Result("file_fd not on file system on bdev_fd");

    return Result();
}

static Result BdevNameDeviceNumberSameAsBdev(std::string& bdev_name, int bdev_fd) {
    DeviceNumber bdev_device_number;
    Result result = BdevGetDeviceNumber(bdev_fd, &bdev_device_number);
    if (result.IsError()) return result;

    DeviceNumber bdev_name_device_number;
    result = BdevNameGetDeviceNumber(bdev_name, &bdev_name_device_number);
    if (result.IsError()) return result;

    if (!bdev_device_number.Equals(bdev_name_device_number))
        return_Result("device numbers different between bdev_name and bdev_fd");

    return Result();
}

static Result BdevGetMainBlkaddrOffset(const std::string& bdev_name, off_t* main_blkaddr_offset) {
    char buf[128];
    *main_blkaddr_offset = 0;

    std::string::size_type index = bdev_name.rfind('/');
    std::string::size_type length = bdev_name.length();
    if (length == 0 || bdev_name[0] != '/' || index == std::string::npos || index + 1 == length)
        return_Result("bdev_name is not absolute");

    std::string main_blkaddr_file = "/sys/fs/f2fs" + bdev_name.substr(index) + "/main_blkaddr";

    int fd = open(main_blkaddr_file.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return_ResultErrno("open() of main_blkaddr for bdev in /sys/fs/f2fs failed", errno);
    ssize_t nread = read(fd, buf, sizeof(buf) - 1);
    int errno_value = errno;  // close() might clobber errno
    close(fd);

    if (nread < 0) return_ResultErrno("read() failed", errno_value);

    buf[nread] = 0;
    errno = 0;  // to use strtoull(3) errno has to be cleared first
    unsigned long long llsz = strtoull(buf, nullptr, 0);
    if (errno) return_ResultErrno("invalid /sys/fs/f2fs main_blkaddr value", errno);

    *main_blkaddr_offset = llsz * kF2fsBlockSize;
    return Result();
}

static Result FileOnF2fsFileSystem(int file_fd) {
    struct statfs sfs;
    if (fstatfs(file_fd, &sfs) < 0) return_ResultErrno("fstafs() failed", errno);

    if (sfs.f_type != F2FS_SUPER_MAGIC) return_Result("fstafs() not a F2FS fs");

    if (sfs.f_bsize != kF2fsBlockSize) return_Result("fstafs() invalid f_bsize");

    return Result();
}

static Result ValidateFileAndBdev(int file_fd, int bdev_fd, std::string& bdev_name,
                                  off_t* main_blkaddr_offset) {
    Result result = FileOnFileSystemOnBdev(file_fd, bdev_fd);
    if (result.IsError()) return result;

    result = BdevNameDeviceNumberSameAsBdev(bdev_name, bdev_fd);
    if (result.IsError()) return result;

    result = FileOnF2fsFileSystem(file_fd);
    if (result.IsError()) return result;

    result = BdevGetMainBlkaddrOffset(bdev_name, main_blkaddr_offset);
    if (result.IsError()) return result;

    return Result();
}

static Result FilePin(int file_fd) {
    uint32_t set = 1;
    if (ioctl(file_fd, F2FS_IOC_SET_PIN_FILE, &set) < 0)
        return_ResultErrno("ioctl() to pin file failed", errno);

    return Result();
}

static Result FileEnsureItsPinned(int file_fd) {
    uint32_t flags = 0;
    if (ioctl(file_fd, FS_IOC_GETFLAGS, &flags) < 0)
        return_ResultErrno("ioctl() F2FS_IOC_GETFLAGS", errno);

    if (!(flags & FS_NOCOW_FL)) return_Result("expected file to be pinned, it is not pinned");

    return Result();
}

static Result FileAllocateAndFsync(int file_fd, off_t size) {
    if (fallocate(file_fd, 0, (off_t)0, size) < 0) return_ResultErrno("fallocate() failed", errno);

    if (fsync(file_fd) < 0) return_ResultErrno("fsync() failed", errno);

    return Result();
}

static Result FileTruncateAndFsync(int file_fd) {
    if (ftruncate(file_fd, (off_t)0) < 0) return_ResultErrno("ftruncate() failed", errno);

    if (fsync(file_fd) < 0) return_ResultErrno("fsync() failed", errno);

    return Result();
}

// Get the first extent within [offset, offset + length), if Result !IsError() then,
// em->em_fiemap.fm_extents contains the extent information.

Result FileGetExtentMap(int file_fd, off_t offset, off_t length, ExtentMap* em) {
    em->em_fiemap.fm_start = uint64_t(offset);
    em->em_fiemap.fm_length = uint64_t(length);
    em->em_fiemap.fm_flags = 0;
    em->em_fiemap.fm_mapped_extents = 0;
    em->em_fiemap.fm_extent_count = 1;

    if (ioctl(file_fd, FS_IOC_FIEMAP, &em->em_fiemap) < 0)
        return_ResultErrno("ioctl() FS_IOC_FIEMAP failed", errno);
    return Result();
}

Result FiemapExtentValidate(FiemapExtent* fe) {
    if (fe->fe_logical > INT64_MAX || fe->fe_physical > INT64_MAX || fe->fe_length > INT64_MAX ||
        fe->fe_length == 0)
        return_Result("invalid extent");

    if (fe->fe_flags & kEntangledDataExtentFlags)
        return_Result("extent flags improper for direct I/O from device");

    if (fe->fe_flags & ~kAllFiemapExtentFlags) return_Result("unknown extent flags");

    return Result();
}

static Result FileVerifyItsReliablyPinned(int file_fd, off_t main_blkaddr_offset) {
    Result result = FileEnsureItsPinned(file_fd);
    if (result.IsError()) return result;

    uint32_t attempts = 0;
    if (ioctl(file_fd, F2FS_IOC_GET_PIN_FILE, &attempts) < 0)
        return_ResultErrno("ioctl() to get internal F2FS file unpinning choice failed", errno);

    if (attempts != 0) return_Result("F2FS will eventually unpin this file");

    off_t file_size;
    result = FileGetSize(file_fd, &file_size);
    if (result.IsError()) return result;

    if (file_size % kF2fsSegmentSize) return_Result("file size is not a multiple of 2MB");

    ExtentMap em;
    FiemapExtent* fe = em.em_fiemap.fm_extents;

    for (off_t offset = 0; offset < file_size;) {
        off_t leftover = file_size - offset;
        result = FileGetExtentMap(file_fd, offset, leftover, &em);
        if (result.IsError()) return result;

        result = FiemapExtentValidate(fe);
        if (result.IsError()) return result;

        if (fe->fe_logical != offset) return_Result("file should not have holes");

        if (fe->fe_length > leftover)
            return_Result("file should not have storage past end of file");

        if (fe->fe_physical < main_blkaddr_offset)
            return_Result("file storage should not be prior to main_blkaddr");

        if ((fe->fe_physical - main_blkaddr_offset) % kF2fsSegmentSize)
            return_Result("extent space is not 2MB aligned with respect to main_blkaddr");

        if (fe->fe_length % kF2fsSegmentSize) return_Result("extent space is not multiple of 2MB");

        offset += fe->fe_length;
        leftover -= fe->fe_length;
    }

    return Result();
}

Result BdevFileSystemSupportsReliablePinning(std::string& bdev_name) {
    off_t main_blkaddr_offset;
    return BdevGetMainBlkaddrOffset(bdev_name, &main_blkaddr_offset);
}

Result FileAllocateSpaceAndReliablyPin(int file_fd, int bdev_fd, std::string& bdev_name,
                                       off_t size) {
    off_t main_blkaddr_offset;
    Result result = ValidateFileAndBdev(file_fd, bdev_fd, bdev_name, &main_blkaddr_offset);
    if (result.IsError()) return result;

    if (size % kF2fsSegmentSize) return_Result("size not a multiple of 2MB");

    off_t file_size;
    result = FileGetSize(file_fd, &file_size);
    if (result.IsError()) return result;

    if (file_size != 0) return_Result("file size is not zero");

    result = FilePin(file_fd);
    if (result.IsError()) return result;

    if ((result = FileAllocateAndFsync(file_fd, size)).IsError() ||
        (result = FileVerifyItsReliablyPinned(file_fd, main_blkaddr_offset)).IsError()) {
        (void)FileTruncateAndFsync(file_fd);
        return result;
    }

    return Result();
}

Result FileEnsureReliablyPinned(int file_fd, int bdev_fd, std::string& bdev_name) {
    off_t main_blkaddr_offset;
    Result result = ValidateFileAndBdev(file_fd, bdev_fd, bdev_name, &main_blkaddr_offset);
    if (result.IsError()) return result;

    if (fsync(file_fd) < 0) return_ResultErrno("fsync() failed", errno);

    return FileVerifyItsReliablyPinned(file_fd, main_blkaddr_offset);
}

}  // namespace android::pin
