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

#define TRACE_TAG ADB

#include "apk_archive.h"

#include "adb_trace.h"
#include "sysdeps.h"

#include <openssl/md5.h>

constexpr uint16_t kCompressStored = 0;

// mask value that signifies that the entry has a DD
static const uint32_t kGPBDDFlagMask = 0x0008;

using com::android::fastdeploy::APKDump;

ApkArchive::ApkArchive(const std::string& path) : path_(path), start_(nullptr), size_(0), fd_(-1) {
    Prepare();
}

ApkArchive::~ApkArchive() {
    adb_munmap(start_, size_);
}

ApkArchive::Location ApkArchive::GetSignatureLocation(size_t offset_to_cdrecord) {
    Location location;
    uint8_t* cdRecord = start_ + offset_to_cdrecord;

    // Check if there is a v2/v3 Signature block here.
    uint8_t* signature = cdRecord - 16;
    if (signature >= start_ && !memcmp((const char*)signature, "APK Sig Block 42", 16)) {
        // This is likely a signature block.
        location.size = *(uint64_t*)(signature - 8);
        location.offset = offset_to_cdrecord - location.size - 8;

        // Check we have the block size at the start and at the end match.
        if (*(uint64_t*)(start_ + location.offset) == location.size) {
            location.valid = true;
        }
    }
    return location;
}

size_t ApkArchive::GetArchiveSize() const {
    struct stat st;
    stat(path_.c_str(), &st);
    return st.st_size;
}

uint8_t* ApkArchive::FindEndOfCDRecord() const {
    constexpr int kMinEndCDRecordSize = 21;
    constexpr int endCDSignature = 0x06054b50;

    // Start scanning from the end
    uint8_t* cursor = start_ + size_ - 1 - kMinEndCDRecordSize;

    // Search for End of Central Directory record signature.
    while (cursor >= start_) {
        if (*(int32_t*)cursor == endCDSignature) {
            return cursor;
        }
        cursor--;
    }
    return nullptr;
}

ApkArchive::Location ApkArchive::FindCDRecord(const uint8_t* cursor) {
    struct ecdr_t {
        uint8_t signature[4];
        uint16_t diskNumber;
        uint16_t numDisk;
        uint16_t diskEntries;
        uint16_t numEntries;
        uint32_t crSize;
        uint32_t offsetToCdHeader;
        uint16_t commnetSize;
        uint8_t comment[0];
    } __attribute__((packed));
    ecdr_t* header = (ecdr_t*)cursor;

    Location location;
    location.offset = header->offsetToCdHeader;
    location.size = header->crSize;
    location.valid = true;
    return location;
}

ApkArchive::Location ApkArchive::GetCDLocation() {
    constexpr int cdRecordFileHeaderSignature = 0x02014b50;
    Location location;

    // Find End of Central Directory Record
    uint8_t* cursor = FindEndOfCDRecord();
    if (cursor == nullptr) {
        fprintf(stderr, "Unable to find End of Central Directory record in file '%s'\n",
                path_.c_str());
        return location;
    }

    // Find Central Directory Record
    location = FindCDRecord(cursor);
    if (cdRecordFileHeaderSignature != *(uint32_t*)(start_ + location.offset)) {
        fprintf(stderr, "Unable to find Central Directory File Header in file '%s'\n",
                path_.c_str());
        return location;
    }

    location.valid = true;
    return location;
}

void ApkArchive::Prepare() {
    // Search End of Central Directory Record
    fd_.reset(adb_open(path_.c_str(), O_RDONLY));
    if (fd_ == -1) {
        fprintf(stderr, "Unable to open file '%s'\n", path_.c_str());
        return;
    }

    size_ = GetArchiveSize();

    start_ = (uint8_t*)adb_mmap(0, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
    if (start_ == MAP_FAILED) {
        fprintf(stderr, "Unable to mmap file '%s'\n", path_.c_str());
        return;
    }
}

std::string ApkArchive::ReadMetadata(Location loc) const {
    return {(const char*)(start_ + loc.offset), loc.size};
}

APKDump ApkArchive::ExtractMetadata() {
    D("ExtractMetadata");
    if (!ready()) {
        return {};
    }

    Location cdLoc = GetCDLocation();
    if (!cdLoc.valid) {
        return {};
    }

    APKDump dump;
    dump.set_absolute_path(path_);
    dump.set_cd(ReadMetadata(cdLoc));

    Location sigLoc = GetSignatureLocation(cdLoc.offset);
    if (sigLoc.valid) {
        dump.set_signature(ReadMetadata(sigLoc));
    }
    return dump;
}

size_t ApkArchive::ParseCentralDirectoryRecord(const char* input, size_t size, std::string* md5Hash,
                                               int64_t* localFileHeaderOffset, int64_t* dataSize) {
    // A structure representing the fixed length fields for a single
    // record in the central directory of the archive. In addition to
    // the fixed length fields listed here, each central directory
    // record contains a variable length "file_name" and "extra_field"
    // whose lengths are given by |file_name_length| and |extra_field_length|
    // respectively.
    static constexpr int kCDFileHeaderMagic = 0x02014b50;
    struct CentralDirectoryRecord {
        // The start of record signature. Must be |kSignature|.
        uint32_t record_signature;
        // Source tool version. Top byte gives source OS.
        uint16_t version_made_by;
        // Tool version. Ignored by this implementation.
        uint16_t version_needed;
        // The "general purpose bit flags" for this entry. The only
        // flag value that we currently check for is the "data descriptor"
        // flag.
        uint16_t gpb_flags;
        // The compression method for this entry, one of |kCompressStored|
        // and |kCompressDeflated|.
        uint16_t compression_method;
        // The file modification time and date for this entry.
        uint16_t last_mod_time;
        uint16_t last_mod_date;
        // The CRC-32 checksum for this entry.
        uint32_t crc32;
        // The compressed size (in bytes) of this entry.
        uint32_t compressed_size;
        // The uncompressed size (in bytes) of this entry.
        uint32_t uncompressed_size;
        // The length of the entry file name in bytes. The file name
        // will appear immediately after this record.
        uint16_t file_name_length;
        // The length of the extra field info (in bytes). This data
        // will appear immediately after the entry file name.
        uint16_t extra_field_length;
        // The length of the entry comment (in bytes). This data will
        // appear immediately after the extra field.
        uint16_t comment_length;
        // The start disk for this entry. Ignored by this implementation).
        uint16_t file_start_disk;
        // File attributes. Ignored by this implementation.
        uint16_t internal_file_attributes;
        // File attributes. For archives created on Unix, the top bits are the
        // mode.
        uint32_t external_file_attributes;
        // The offset to the local file header for this entry, from the
        // beginning of this archive.
        uint32_t local_file_header_offset;

      private:
        CentralDirectoryRecord() = default;
        DISALLOW_COPY_AND_ASSIGN(CentralDirectoryRecord);
    } __attribute__((packed));

    const CentralDirectoryRecord* cdr;
    if (size < sizeof(*cdr)) {
        return {};
    }

    auto begin = input;
    cdr = reinterpret_cast<const CentralDirectoryRecord*>(begin);
    if (cdr->record_signature != kCDFileHeaderMagic) {
        fprintf(stderr, "Invalid Central Directory Record signature\n");
        return {};
    }
    auto end = begin + sizeof(*cdr) + cdr->file_name_length + cdr->extra_field_length +
               cdr->comment_length;

    uint8_t md5Digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)begin, end - begin, md5Digest);
    md5Hash->assign((const char*)md5Digest, sizeof(md5Digest));

    *localFileHeaderOffset = cdr->local_file_header_offset;
    *dataSize = (cdr->compression_method == kCompressStored) ? cdr->uncompressed_size
                                                             : cdr->compressed_size;

    return end - begin;
}

size_t ApkArchive::CalculateLocalFileEntrySize(int64_t localFileHeaderOffset,
                                               int64_t dataSize) const {
    // The local file header for a given entry. This duplicates information
    // present in the central directory of the archive. It is an error for
    // the information here to be different from the central directory
    // information for a given entry.
    static constexpr int kLocalFileHeaderMagic = 0x04034b50;
    struct LocalFileHeader {
        // The local file header signature, must be |kSignature|.
        uint32_t lfh_signature;
        // Tool version. Ignored by this implementation.
        uint16_t version_needed;
        // The "general purpose bit flags" for this entry. The only
        // flag value that we currently check for is the "data descriptor"
        // flag.
        uint16_t gpb_flags;
        // The compression method for this entry, one of |kCompressStored|
        // and |kCompressDeflated|.
        uint16_t compression_method;
        // The file modification time and date for this entry.
        uint16_t last_mod_time;
        uint16_t last_mod_date;
        // The CRC-32 checksum for this entry.
        uint32_t crc32;
        // The compressed size (in bytes) of this entry.
        uint32_t compressed_size;
        // The uncompressed size (in bytes) of this entry.
        uint32_t uncompressed_size;
        // The length of the entry file name in bytes. The file name
        // will appear immediately after this record.
        uint16_t file_name_length;
        // The length of the extra field info (in bytes). This data
        // will appear immediately after the entry file name.
        uint16_t extra_field_length;

      private:
        LocalFileHeader() = default;
        DISALLOW_COPY_AND_ASSIGN(LocalFileHeader);
    } __attribute__((packed));
    CHECK(ready()) << path_;

    const LocalFileHeader* lfh;
    if (localFileHeaderOffset + sizeof(*lfh) > size_) {
        fprintf(stderr,
                "Invalid Local File Header offset in file '%s' at offset %lld, file size %lld\n",
                path_.c_str(), (long long)localFileHeaderOffset, (long long)size_);
        return {};
    }

    lfh = reinterpret_cast<const LocalFileHeader*>(start_ + localFileHeaderOffset);
    if (lfh->lfh_signature != kLocalFileHeaderMagic) {
        fprintf(stderr, "Invalid Local File Header signature in file '%s' at offset %lld\n",
                path_.c_str(), (long long)localFileHeaderOffset);
        return {};
    }

    // The *optional* data descriptor start signature.
    static constexpr int kOptionalDataDescriptorMagic = 0x08074b50;
    struct DataDescriptor {
        // CRC-32 checksum of the entry.
        uint32_t crc32;
        // Compressed size of the entry.
        uint32_t compressed_size;
        // Uncompressed size of the entry.
        uint32_t uncompressed_size;

      private:
        DataDescriptor() = default;
        DISALLOW_COPY_AND_ASSIGN(DataDescriptor);
    };

    auto ddOffset = localFileHeaderOffset + sizeof(*lfh) + lfh->file_name_length +
                    lfh->extra_field_length + dataSize;
    int64_t ddSize = 0;

    int64_t localDataSize;
    if (lfh->gpb_flags & kGPBDDFlagMask) {
        // There is trailing data descriptor.
        const DataDescriptor* dd;

        if (ddOffset + sizeof(uint32_t) > size_) {
            fprintf(stderr,
                    "Error reading trailing data descriptor signature in file '%s' at offset %lld, "
                    "file size %lld\n",
                    path_.c_str(), (long long)ddOffset, (long long)size_);
            return {};
        }
        if (kOptionalDataDescriptorMagic == *(uint32_t*)(start_ + ddOffset)) {
            ddOffset += sizeof(uint32_t);
            ddSize += sizeof(uint32_t);
        }
        if (ddOffset + sizeof(*dd) > size_) {
            fprintf(stderr,
                    "Error reading trailing data descriptor in file '%s' at offset %lld, file size "
                    "%lld\n",
                    path_.c_str(), (long long)ddOffset, (long long)size_);
            return {};
        }

        dd = reinterpret_cast<const DataDescriptor*>(start_ + ddOffset);
        localDataSize = (lfh->compression_method == kCompressStored) ? dd->uncompressed_size
                                                                     : dd->compressed_size;
        ddSize += sizeof(*dd);
    } else {
        localDataSize = (lfh->compression_method == kCompressStored) ? lfh->uncompressed_size
                                                                     : lfh->compressed_size;
    }
    if (localDataSize != dataSize) {
        fprintf(stderr,
                "Data sizes mismatch in file '%s' at offset %lld, CDr: %lld vs LHR/DD: %lld\n",
                path_.c_str(), (long long)(localFileHeaderOffset), (long long)dataSize,
                (long long)localDataSize);
        return {};
    }

    return sizeof(*lfh) + lfh->file_name_length + lfh->extra_field_length + dataSize + ddSize;
}
