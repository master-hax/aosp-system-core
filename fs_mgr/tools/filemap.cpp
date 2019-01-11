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

#include <assert.h>
#include <errno.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#if !defined(STAND_ALONE_TO_TEST_ON_LINUX)
#include <android-base/unique_fd.h>
typedef android::base::unique_fd UniqueFd;
#else
typedef int UniqueFd;
#endif

template <typename T>
std::string HexString(T offset) {
    constexpr int FW = 2 * sizeof(offset);
    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(FW) << std::hex << offset;
    return ss.str();
}

void FilePrintExtentMap(const std::string& cmd, const std::string& file);
void FileRead(const std::string& cmd, const std::string& bdev, const std::string& file);
void FileFlip(const std::string& cmd, const std::string& bdev, const std::string& file);

class FileMap {
  public:
    struct Extent {
        off_t logical;
        off_t physical;
        off_t length;
        uint32_t flags;
    };

    FileMap() {}

    FileMap(const std::string& file_name) : file_fd_(OpenDuringConstruction(file_name, O_RDONLY)) {
        if (construction_error_) return;
        construction_error_ = ReadExtents();
    }

    FileMap(const std::string& bdev_name, bool read_only, const std::string& file_name)
        : bdev_fd_(OpenDuringConstruction(bdev_name, read_only ? O_RDONLY : O_RDWR)),
          file_fd_(OpenDuringConstruction(file_name, O_RDONLY)) {
        if (construction_error_) return;
        construction_error_ = ReadExtents();
    }

    FileMap(const std::string& bdev_name, const std::string& file_name, off_t size)
        : bdev_fd_(OpenDuringConstruction(bdev_name, O_RDONLY)),
          file_fd_(OpenDuringConstruction(file_name, O_CREAT | O_EXCL | O_RDWR)) {
        if (construction_error_) return;
        construction_error_ = AllocateFileSpace(size);
        if (!construction_error_) {
            construction_error_ = ReadExtents();
            if (!construction_error_) return;
        }
        DeleteFile(file_name);
    }

    ~FileMap() {}

    int Print();
    int PrintExtents();
    int CopyFileData(int dest_fd);
    int BitFlip();
    int WriteAndVerifyFile();
    int VerifyPattern();

    static constexpr off_t kPhysicalHole = off_t(-1);

    int ConstructionError() { return construction_error_; }
    int BlockSize() const { return block_size_; }
    off_t FileSize() const { return file_size_; }
    off_t BytesInExtents() const { return bytes_in_extents_; }
    off_t BytesInHoles() const { return bytes_in_holes_; }
    off_t BytesPastEof() const { return bytes_past_eof_; }
    std::string ErrorString(int error);
    static int StringToSize(const std::string& str, off_t* size);

  private:
    //  Must be first, OpenDuringConstruction() uses it while opening file
    //  descriptor argument to the constructors for: bdev_fd_ and file_fd_
    int construction_error_ = 0;

    //  Must all be prior to the construction of the unique_fd below, the
    //  construction of bdev_fd_ and file_fd_ open the file and bdev and
    //  read the extent map, file size, block size, etc. so the construction
    //  of these members must occur prior to that.
    int block_size_ = 0;
    off_t file_size_ = 0;
    off_t bytes_in_extents_ = 0;
    off_t bytes_in_holes_ = 0;
    off_t bytes_past_eof_ = 0;
    uint32_t summary_of_extent_flags_ = 0;
    bool unaligned_extents_ = false;
    std::string error_string_;
    std::vector<Extent> extents_;

    //  Must be the last data members, requires that the prior members be
    //  constructed first.
    UniqueFd bdev_fd_;
    UniqueFd file_fd_;

    int ReReadExtents() {
        block_size_ = 0;
        file_size_ = 0;
        bytes_in_extents_ = 0;
        bytes_in_holes_ = 0;
        bytes_past_eof_ = 0;
        summary_of_extent_flags_ = 0;
        unaligned_extents_ = false;
        extents_.clear();

        int error = EnsureFileIsSet();
        if (error) return error;
        return ReadExtents();
    }

    typedef struct fiemap Fiemap;
    typedef struct fiemap_extent FiemapExtent;

    struct ExtentMap {
        Fiemap em_fiemap;
        FiemapExtent em_extents[1];
    };

    static constexpr uint32_t kEntangledDataExtentFlags =
            FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC | FIEMAP_EXTENT_ENCODED |
            FIEMAP_EXTENT_DATA_ENCRYPTED | FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_DATA_INLINE |
            FIEMAP_EXTENT_DATA_TAIL | FIEMAP_EXTENT_UNWRITTEN | FIEMAP_EXTENT_MERGED |
            FIEMAP_EXTENT_SHARED;

    static constexpr uint32_t kAllFiemapExtentFlags =
            FIEMAP_EXTENT_LAST | kEntangledDataExtentFlags;

    int EnsureFileIsSet() {
        if (construction_error_) return construction_error_;
        return file_fd_ < 0 ? FileIsNotSet : 0;
    }

    int EnsureFileAndBdevAreSet() {
        if (construction_error_) return construction_error_;
        return file_fd_ < 0 ? FileIsNotSet : bdev_fd_ < 0 ? BdevIsNotSet : 0;
    }

    //  To satisfy the needs of unique_fd (to be set at construction time) and because returning
    //  errors via a pointer argument out of the constructor is not an idiom used in Android
    //  this function is used to do an open() and return the file descriptor used to construct
    //  the unique_fd for file_fd_ or bdev_fd_

    int OpenDuringConstruction(const std::string& file_name, int oflag) {
        if (construction_error_) return -1;  // something else failed before
        const char* name = file_name.c_str();
        int fd = open(name, oflag | O_CLOEXEC, 0600);
        if (fd < 0) {
            SetErrorQuotedStringWithPosixErrno(name);
            construction_error_ = OpenFileFailed;
        }
        return fd;
    }

    int DeleteFile(const std::string& file_name) {
        const char* name = file_name.c_str();
        if (unlink(name) >= 0) return 0;
        SetErrorQuotedStringWithPosixErrno(name);
        return DeleteFileFailed;
    }

    int GetBlockSize() {
        if (ioctl(file_fd_, FIGETBSZ, &block_size_) < 0) {
            SetErrorStringWithPosixErrno("I/O control FIGETBSZ");
            return GetBlockSizeFailed;
        }
        if (block_size_ & (block_size_ - 1)) return BlockSizeNotPowerOfTwo;
        return 0;
    }

    int GetFileSize() {
        struct stat st;
        if (fstat(file_fd_, &st) < 0) {
            SetErrorStringWithPosixErrno("fstat() on file");
            return GetFileSizeFailed;
        }
        file_size_ = st.st_size;
        return 0;
    }

    void PushBackHole(off_t logical, off_t length) {
        extents_.emplace_back(Extent{
                .logical = logical, .physical = kPhysicalHole, .length = length, .flags = 0});
    }

    int ValidateExtent(FiemapExtent* fe) {
        if (fe->fe_logical > INT64_MAX || fe->fe_physical > INT64_MAX ||
            fe->fe_length > INT64_MAX || fe->fe_length == 0)
            return InvalidExtent;
        return 0;
    }

    void PushBackExtent(FiemapExtent* fe) {
        extents_.emplace_back(Extent{.logical = off_t(fe->fe_logical),
                                     .physical = off_t(fe->fe_physical),
                                     .length = off_t(fe->fe_length),
                                     .flags = fe->fe_flags});
    }

    int ComplicatedExtents() {
        if (unaligned_extents_) return UnalignedExtents;
        if (summary_of_extent_flags_ & kEntangledDataExtentFlags) return EntangledExtents;
        if (summary_of_extent_flags_ & ~kAllFiemapExtentFlags) return UnknownExtentFlags;
        return 0;
    }

    static void PrintHole(off_t logical, off_t length) {
        std::cout << HexString(logical) << " logical\n";
        std::cout << "hole               physical\n";
        std::cout << HexString(length) << " length\n";
    }

    static void PrintExtent(Extent* ex) {
        std::cout << HexString(ex->logical) << " logical\n";
        std::cout << HexString(ex->physical) << " physical\n";
        std::cout << HexString(ex->length) << " length\n";
        std::cout << HexString(ex->flags) << " flags\n";
        PrintExtentFlags(ex->flags);
    }

    static void PrintExtentFlags(uint32_t flags) {
        struct FlagMap {
            uint32_t fl_flag;
            std::string fl_name;
        };
        static const FlagMap flag_map[] = {
                {FIEMAP_EXTENT_LAST, "FIEMAP_EXTENT_LAST"},
                {FIEMAP_EXTENT_UNKNOWN, "FIEMAP_EXTENT_UNKNOWN"},
                {FIEMAP_EXTENT_DELALLOC, "FIEMAP_EXTENT_DELALLOC"},
                {FIEMAP_EXTENT_ENCODED, "FIEMAP_EXTENT_ENCODED"},
                {FIEMAP_EXTENT_DATA_ENCRYPTED, "FIEMAP_EXTENT_DATA_ENCRYPTED"},
                {FIEMAP_EXTENT_NOT_ALIGNED, "FIEMAP_EXTENT_NOT_ALIGNED"},
                {FIEMAP_EXTENT_DATA_INLINE, "FIEMAP_EXTENT_DATA_INLINE"},
                {FIEMAP_EXTENT_DATA_TAIL, "FIEMAP_EXTENT_DATA_TAIL"},
                {FIEMAP_EXTENT_UNWRITTEN, "FIEMAP_EXTENT_UNWRITTEN"},
                {FIEMAP_EXTENT_MERGED, "FIEMAP_EXTENT_MERGED"},
                {FIEMAP_EXTENT_SHARED, "FIEMAP_EXTENT_SHARED"},
        };
        if (flags & ~kAllFiemapExtentFlags) {
            std::cout << "    unknown: " << HexString(flags & ~kAllFiemapExtentFlags) << std::endl;
            flags &= ~kAllFiemapExtentFlags;
        }
        const FlagMap* fl = flag_map;
        const FlagMap* flend = fl + sizeof(flag_map) / sizeof(flag_map[0]);
        for (; fl < flend; ++fl)
            if (flags & fl->fl_flag) std::cout << "    " << fl->fl_name << std::endl;
    }

    int AllocateFileSpace(off_t size) {
        if (fallocate(file_fd_, 0, off_t(0), size) < 0) {
            SetErrorStringWithPosixErrno("fallocate() on file");
            return AllocateFileSpaceFailed;
        }
        return 0;
    }

    //  DO NOT receive s as a std::string just in case its construction clears errno
    void SetErrorStringWithPosixErrno(const char* s) {
        const char* se = strerror(errno);
        // DO NOT move strerror(errno) into this expression, in case it affects errno
        error_string_ = ": " + std::string(s) + " with: " + std::string(se);
    }

    //  DO NOT receive s as a std::string just in case its construction clears errno
    void SetErrorQuotedStringWithPosixErrno(const char* s) {
        const char* se = strerror(errno);
        // DO NOT move strerror(errno) into this expression, in case it affects errno
        error_string_ = ": \"" + std::string(s) + "\" with: " + std::string(se);
    }

    int ReadExtents();
    int CopyHoleData(off_t length, int dest_fd);
    int CopyExtentData(off_t physical, off_t length, off_t ncopy, int dest_fd);
    int BitFlipExtent(off_t physical, off_t length);
    int WritePattern();

    //  These internal error values are negative to ensure they are disjoint from
    //  POSIX errno values, even though POSIX errno values and these values never mix
    enum {
        PartialRead = -100,
        PartialWrite,
        EntangledExtents,
        BlockSizeNotPowerOfTwo,
        InvalidExtent,
        InvalidFiemapResult,
        UnknownExtentFlags,
        UnexpectedHole,
        UnexpectedSpacePastEof,
        UnexpectedData,
        FileSizeNotMultipleOfBlockSize,
        FileIsNotSet,
        BdevIsNotSet,
        UnalignedExtents,

        OpenFileFailed,
        DeleteFileFailed,
        GetBlockSizeFailed,
        GetFileSizeFailed,
        AllocateFileSpaceFailed,
        ReadExtentsFailed,
        WriteAndVerifyFileFailed,
        WritePatternFailed,
        VerifyPatternFailed,
        CopyHoleDataFailed,
        CopyExtentDataFailed,
        BitFlipExtentFailed,
        StringToSizeFailed,
    };
};

std::string FileMap::ErrorString(int error) {
    //  safety net, no POSIX errno value should reach here
    if (error > 0) return strerror(error);

    const char* e = "unknown error";
    switch (error) {
        case PartialRead:
            e = "partial read";
            break;
        case PartialWrite:
            e = "partial write";
            break;
        case EntangledExtents:
            e = "entangled extents";
            break;
        case BlockSizeNotPowerOfTwo:
            e = "block size is not a power of two";
            break;
        case InvalidExtent:
            e = "invalid extent";
            break;
        case InvalidFiemapResult:
            e = "invalid fiemap result";
            break;
        case UnknownExtentFlags:
            e = "unknown extent flags";
            break;
        case UnexpectedHole:
            e = "unexpected hole";
            break;
        case UnexpectedSpacePastEof:
            e = "unexpected space past end of file";
            break;
        case UnexpectedData:
            e = "unexpected data";
            break;
        case FileSizeNotMultipleOfBlockSize:
            e = "file size not multiple of block size";
            break;
        case FileIsNotSet:
            e = "file is not set";
            break;
        case BdevIsNotSet:
            e = "block device is not set";
            break;
        case UnalignedExtents:
            e = "extent length not block size multiple, or not logically or physically aligned";
            break;
        case OpenFileFailed:
            e = "open file failed";
            break;
        case DeleteFileFailed:
            e = "delete file failed";
            break;
        case GetBlockSizeFailed:
            e = "get block size failed";
            break;
        case AllocateFileSpaceFailed:
            e = "allocate file space failed";
            break;
        case GetFileSizeFailed:
            e = "get file size failed";
            break;
        case ReadExtentsFailed:
            e = "read extents failed";
            break;
        case WriteAndVerifyFileFailed:
            e = "write and verify file failed";
            break;
    }
    std::string result = e + error_string_;
    error_string_.clear();
    return result;
}

void PrintErrorAndExit(const std::string& cmd, int error, const FileMap& filemap);
void PrintErrorStringAndExit(const std::string& cmd, const std::string& str);
char* CommandName(char* c);
void Usage(const std::string& cmd);

static_assert(sizeof((struct fiemap_extent*)nullptr)->fe_flags == sizeof(uint32_t),
              "fe_flags has wrong size");

int FileMap::ReadExtents() {
    int error = EnsureFileIsSet();
    if (error) return error;

    error = GetBlockSize();
    if (error) return error;

    error = GetFileSize();
    if (error) return error;

    off_t block_mask = block_size_ - 1;
    off_t bytes_in_extents = 0;
    off_t bytes_in_holes = 0;
    off_t bytes_past_eof = 0;
    bool unaligned_extents = false;

    uint32_t summary = 0;

    for (off_t length = file_size_, logical = 0; logical < file_size_;) {
        ExtentMap em = {.em_fiemap = {.fm_start = uint64_t(logical),
                                      .fm_length = uint64_t(length),
                                      .fm_flags = 0,
                                      .fm_extent_count = 1,
                                      .fm_mapped_extents = 0}};

        FiemapExtent* ex = em.em_fiemap.fm_extents;
        if (ioctl(file_fd_, FS_IOC_FIEMAP, &em.em_fiemap) < 0) {
            SetErrorStringWithPosixErrno("I/O control FS_IOC_FIEMAP");
            return ReadExtentsFailed;
        }
        if (em.em_fiemap.fm_mapped_extents != 1) {
            if (em.em_fiemap.fm_mapped_extents != 0) return InvalidFiemapResult;
            PushBackHole(logical, length);
            bytes_in_holes += length;
            break;
        }

        error = ValidateExtent(ex);
        if (error) return error;

        summary |= ex->fe_flags;
        off_t exlength = ex->fe_length;
        off_t exlogical = ex->fe_logical;
        off_t exphysical = ex->fe_physical;

        off_t new_logical = exlogical + exlength;
        off_t skip = new_logical - logical;

        if (skip != exlength) {
            if (skip < exlength) return InvalidFiemapResult;
            off_t hole_length = skip - exlength;
            PushBackHole(logical, hole_length);
            bytes_in_holes += hole_length;
        }

        PushBackExtent(ex);

        if ((exlength | exlogical | exphysical) & block_mask) unaligned_extents = true;

        if (new_logical > file_size_) {
            if (exlogical < file_size_)
                bytes_past_eof += exlength - (file_size_ - exlogical);
            else
                bytes_past_eof += exlength;
        }

        bytes_in_extents += exlength;
        length -= skip;
        logical = new_logical;
    }

    if (file_size_ != bytes_in_extents + bytes_in_holes - bytes_past_eof)
        return InvalidFiemapResult;

    unaligned_extents_ = unaligned_extents;
    summary_of_extent_flags_ = summary;
    bytes_in_extents_ = bytes_in_extents;
    bytes_in_holes_ = bytes_in_holes;
    bytes_past_eof_ = bytes_past_eof;

    return 0;
}

int FileMap::PrintExtents() {
    int error = EnsureFileIsSet();
    if (error) return error;

    for (Extent& ex : extents_) {
        if (ex.physical == kPhysicalHole)
            PrintHole(ex.logical, ex.length);
        else
            PrintExtent(&ex);
        std::cout << std::endl;
    }
    return 0;
}

int FileMap::Print() {
    int error = EnsureFileIsSet();
    if (error) return error;

    error = PrintExtents();
    if (error) return error;

    std::cout << HexString(BlockSize()) << " block size\n";
    std::cout << HexString(FileSize()) << " file size\n";
    std::cout << HexString(BytesInExtents()) << " total bytes in extents\n";
    std::cout << HexString(BytesInHoles()) << " total bytes in holes\n";
    std::cout << HexString(BytesPastEof()) << " extra space past eof\n";

    return 0;
}

int FileMap::BitFlip() {
    int error = EnsureFileAndBdevAreSet();
    if (error) return error;

    error = ComplicatedExtents();
    if (error) return error;

    for (Extent& ex : extents_) {
        if (ex.physical != kPhysicalHole) {
            error = BitFlipExtent(ex.physical, ex.length);
            if (error) return error;
        }
    }
    return 0;
}

//  Write a pattern on the file and verify it by reading it thorugh bdev.

int FileMap::WriteAndVerifyFile() {
    int error = EnsureFileAndBdevAreSet();
    if (error) return error;

    if (file_size_ & (block_size_ - 1)) return FileSizeNotMultipleOfBlockSize;

    error = WritePattern();
    if (error) return error;

    if (fsync(file_fd_) < 0) {
        SetErrorStringWithPosixErrno("fsync() on file");
        return WriteAndVerifyFileFailed;
    }

    error = ReReadExtents();
    if (error) return error;

    error = VerifyPattern();
    if (error) return error;

    return 0;
}

//  Write through the file system a pattern of uint64_t: 0, 1, 2, ...

int FileMap::WritePattern() {
    constexpr size_t kBlockSize = 64 * 1024;
    uint64_t block[kBlockSize / sizeof(uint64_t)];
    uint64_t* end = block + kBlockSize / sizeof(uint64_t);
    uint64_t value = 0;

    for (off_t off = 0, remaining = file_size_; remaining > 0;) {
        for (uint64_t* p = block; p < end;) *p++ = value++;
        size_t n = remaining > kBlockSize ? kBlockSize : remaining;
        ssize_t written = write(file_fd_, block, n);
        if (written != n) {
            if (written < 0) {
                SetErrorStringWithPosixErrno("write() to file");
                return WritePatternFailed;
            }
            return PartialWrite;
        }
        off += kBlockSize;
        remaining -= written;
    }

    return 0;
}

//  Read from the bdev and verify a pattern of uint64_t: 0, 1, 2, ...

int FileMap::VerifyPattern() {
    if (file_size_ & (block_size_ - 1)) return FileSizeNotMultipleOfBlockSize;

    int error = ComplicatedExtents();
    if (error) return error;

    if (bytes_in_holes_ > 0) return UnexpectedHole;
    if (bytes_past_eof_ > 0) return UnexpectedSpacePastEof;

    constexpr size_t kBlockSize = 64 * 1024;
    uint64_t block[kBlockSize / sizeof(uint64_t)];
    uint64_t value = 0;

    for (Extent& ex : extents_) {
        off_t physical = ex.physical;
        off_t length = ex.length;
        if (physical == kPhysicalHole) return UnexpectedHole;
        if (ex.logical + length > file_size_) return UnexpectedSpacePastEof;

        while (length > 0) {
            size_t n = length > kBlockSize ? kBlockSize : length;
            ssize_t nread = pread(bdev_fd_, block, n, physical);
            if (nread < 0) {
                SetErrorStringWithPosixErrno("pread() from bdev");
                return VerifyPatternFailed;
            }
            if (nread != n) return PartialRead;
            uint64_t* end = block + n / sizeof(uint64_t);
            for (uint64_t* p = block; p < end; ++p, ++value)
                if (*p != value) return UnexpectedData;
            physical += n;
            length -= n;
        }
    }

    return 0;
}

//  Copy the contents of the (by file reading its extents) into dest_fd.

int FileMap::CopyFileData(int dest_fd) {
    int error = EnsureFileAndBdevAreSet();
    if (error) return error;

    error = ComplicatedExtents();
    if (error) return error;

    for (Extent& ex : extents_) {
        if (ex.physical == kPhysicalHole) {
            error = CopyHoleData(ex.length, dest_fd);
            if (error) return error;
        } else {
            if (ex.logical >= file_size_) return 0;
            off_t ncopy =
                    (ex.logical + ex.length > file_size_) ? file_size_ - ex.logical : ex.length;
            error = CopyExtentData(ex.physical, ex.length, ncopy, dest_fd);
            if (error) return error;
        }
    }
    return 0;
}

//  Read from hole and write its contents to dest_fd, i.e. write length zeroes.

int FileMap::CopyHoleData(off_t length, int dest_fd) {
    char buf[4096];
    memset(buf, 0, sizeof(buf));
    off_t leftover = length;

    while (leftover > 0) {
        size_t n = length > sizeof(buf) ? sizeof(buf) : length;
        ssize_t nwritten = write(dest_fd, buf, n);
        if (nwritten != n) {
            if (nwritten < 0) {
                SetErrorStringWithPosixErrno("write() to dest_fd failed");
                return CopyHoleDataFailed;
            }
            return PartialWrite;
        }
        leftover -= n;
    }
    return 0;
}

//  Read from extent and write its contents to fd. Only copy up
//  to ncopy bytes so that bytes past end of file are not copyed.

int FileMap::CopyExtentData(off_t physical, off_t length, off_t ncopy, int dest_fd) {
    char buf[4096];
    off_t leftover = length;
    off_t ncp = ncopy;

    while (leftover > 0 && ncp > 0) {
        size_t n = length > sizeof(buf) ? sizeof(buf) : length;
        ssize_t nread = pread(bdev_fd_, buf, n, physical);
        if (nread != n) {
            if (nread < 0) {
                SetErrorStringWithPosixErrno("pread() on bdev failed");
                return CopyExtentDataFailed;
            }
            return PartialRead;
        }

        if (ncp < n) n = ncp;

        ssize_t nwritten = write(dest_fd, buf, n);
        if (nwritten != n) {
            if (nwritten < 0) {
                SetErrorStringWithPosixErrno("write() to dest_fd failed");
                return CopyExtentDataFailed;
            }
            return PartialWrite;
        }

        leftover -= n;
        physical += n;
        ncp -= n;
    }
    return 0;
}

//  Bitwise invert the contents of an extent.

int FileMap::BitFlipExtent(off_t physical, off_t length) {
    unsigned char buf[4096];
    off_t leftover = length;

    while (leftover > 0) {
        size_t n = length > sizeof(buf) ? sizeof(buf) : length;
        ssize_t nread = pread(bdev_fd_, buf, n, physical);
        if (nread != n) {
            if (nread < 0) {
                SetErrorStringWithPosixErrno("pread() on bdev failed");
                return BitFlipExtentFailed;
            }
            return PartialRead;
        }

        for (unsigned char* p = buf; p < &buf[sizeof(buf)]; ++p) *p = ~*p;

        ssize_t nwritten = pwrite(bdev_fd_, buf, n, physical);
        if (nwritten != n) {
            if (nwritten < 0) {
                SetErrorStringWithPosixErrno("pwrite() on bdev failed");
                return BitFlipExtentFailed;
            }
            return PartialWrite;
        }

        leftover -= n;
        physical += n;
    }
    return 0;
}

int FileMap::StringToSize(const std::string& str, off_t* size) {
    *size = 0;
    const char* ptr = str.c_str();
    char* endptr = nullptr;
    errno = 0;  // to use strtoull(3) errno has to be cleared first
    unsigned long long llsz = strtoull(ptr, &endptr, 0);
    if (errno) return StringToSizeFailed;
    if (endptr == ptr || !endptr || llsz > INT64_MAX) return StringToSizeFailed;
    if (*endptr) {
        if (endptr[1]) return StringToSizeFailed;
        unsigned int shift;
        switch (*endptr) {
            default:
                return StringToSizeFailed;
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
        if (llsz > (INT64_MAX >> shift)) return StringToSizeFailed;
        llsz <<= shift;
    }
    *size = off_t(llsz);
    return 0;
}

void PrintErrorAndExit(const std::string& cmd, int error, FileMap& file_map) {
    std::cerr << cmd << ": error: " << file_map.ErrorString(error) << std::endl;
    exit(1);
}

void PrintErrorStringAndExit(const std::string& cmd, const std::string& str) {
    std::cerr << cmd << ": error: " << str << std::endl;
    exit(1);
}

void FilePrintExtentMap(const std::string& cmd, const std::string& file) {
    FileMap file_map(file);
    int error = file_map.ConstructionError();
    if (error) PrintErrorAndExit(cmd, error, file_map);

    error = file_map.Print();
    if (error) PrintErrorAndExit(cmd, error, file_map);

    exit(0);
}

void FileRead(const std::string& cmd, const std::string& bdev, const std::string& file) {
    FileMap file_map(bdev, true, file);
    int error = file_map.ConstructionError();
    if (error) PrintErrorAndExit(cmd, error, file_map);

    error = file_map.CopyFileData(1);
    if (error) PrintErrorAndExit(cmd, error, file_map);
}

void FileFlip(const std::string& cmd, const std::string& bdev, const std::string& file) {
    FileMap file_map(bdev, false, file);
    int error = file_map.ConstructionError();
    if (error) PrintErrorAndExit(cmd, error, file_map);

    error = file_map.BitFlip();
    if (error) PrintErrorAndExit(cmd, error, file_map);
}

void FileCreate(const std::string& cmd, const std::string& bdev, const std::string& size,
                const std::string& file) {
    off_t sz;

    int error = FileMap::StringToSize(size, &sz);
    if (error) PrintErrorStringAndExit(cmd, std::string("invalid file size"));

    FileMap file_map(bdev, file, sz);
    error = file_map.ConstructionError();
    if (error) PrintErrorAndExit(cmd, error, file_map);

    error = file_map.WriteAndVerifyFile();
    if (error) PrintErrorAndExit(cmd, error, file_map);
}

void FileValidate(const std::string& cmd, const std::string& bdev, const std::string& file) {
    FileMap file_map(bdev, true, file);
    int error = file_map.ConstructionError();
    if (error) PrintErrorAndExit(cmd, error, file_map);

    error = file_map.VerifyPattern();
    if (error) PrintErrorAndExit(cmd, error, file_map);
}

char* CommandName(char* c) {
    char* p = strrchr(c, '/');
    return p ? p + 1 : c;
}

void Usage(const std::string& cmd) {
    std::cerr << "usage: " << cmd
              << " [-r bdev | -x bdev | -c bdev size | -v bdev ] file\n"
                 "\n"
                 "  default:\n"
                 "       Dump extent map of file.\n"
                 "\n"
                 "  -r bdev\n"
                 "       Read contents of file from bdev \n"
                 "       and write it to standard output.\n"
                 "\n"
                 "  -x bdev\n"
                 "       Dead contents of file from bdev \n"
                 "       bitwise invert it and write it back.\n"
                 "\n"
                 "  -c bdev size\n"
                 "       Create file of size bytes, size must be a\n"
                 "       multiple of the filesystem block size.\n"
                 "\n"
                 "       The size can be in decimal, hex, or octal;\n"
                 "       units of k, m, or g (i.e. KB, MB, or GB) can\n"
                 "       appended to it, e.g.: 64m, 0x1000, 0177k.\n"
                 "\n"
                 "       Initialize it to a pattern for validation and\n"
                 "       validate its extent map and contents through bdev.\n"
                 "\n"
                 "  -v bdev\n"
                 "       Validate data of file written with -c.\n"
                 "\n";
    exit(1);
}

int main(int argc, char* argv[]) {
    std::string cmd(CommandName(argv[0]));

    if (argc == 2) {
        std::string file(argv[1]);
        FilePrintExtentMap(cmd, file);
        exit(0);
    }
    if (argc == 4) {
        std::string bdev(argv[2]);
        std::string file(argv[3]);
        if (strcmp(argv[1], "-r") == 0) {
            FileRead(cmd, bdev, file);
            exit(0);
        }
        if (strcmp(argv[1], "-x") == 0) {
            FileFlip(cmd, bdev, file);
            exit(0);
        }
        if (strcmp(argv[1], "-v") == 0) {
            FileValidate(cmd, bdev, file);
            exit(0);
        }
    } else if (argc == 5) {
        if (strcmp(argv[1], "-c") == 0) {
            std::string bdev(argv[2]);
            std::string size(argv[3]);
            std::string file(argv[4]);
            FileCreate(cmd, bdev, size, file);
            exit(0);
        }
    }
    Usage(cmd);
}
