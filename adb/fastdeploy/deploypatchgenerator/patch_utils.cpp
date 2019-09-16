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

#include "patch_utils.h"

#include <androidfw/ZipFileRO.h>
#include <stdio.h>

#include "adb_io.h"
#include "android-base/endian.h"
#include "sysdeps.h"

using namespace com::android;
using namespace com::android::fastdeploy;
using namespace android::base;

static constexpr char kSignature[] = "FASTDEPLOY";

APKMetaData PatchUtils::GetAPKMetaData(const APKDump& apk_dump) {
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

    APKMetaData apkMetaData;
    apkMetaData.set_absolute_path(apk_dump.absolute_path());

    const auto& cd = apk_dump.cd();
    for (auto cur = cd.data(), end = cd.data() + cd.size();
         cur <= end - sizeof(CentralDirectoryRecord);) {
        const auto* cdr = reinterpret_cast<const CentralDirectoryRecord*>(cur);
        cur += sizeof(*cdr);
        if (cdr->record_signature != kCDFileHeaderMagic) {
            break;
        }

        std::string filename;
        filename.assign(cur, cdr->file_name_length);
        cur += cdr->file_name_length + cdr->extra_field_length + cdr->comment_length;

        auto apkEntry = apkMetaData.add_entries();
        apkEntry->set_crc32(cdr->crc32);
        apkEntry->set_filename(std::move(filename));
        apkEntry->set_compressedsize(cdr->compressed_size);
        apkEntry->set_dataoffset(cdr->local_file_header_offset);
    }
    return apkMetaData;
}

APKMetaData PatchUtils::GetAPKMetaData(const char* apkPath) {
    APKMetaData apkMetaData;
    apkMetaData.set_absolute_path(apkPath);
#undef open
    std::unique_ptr<android::ZipFileRO> zipFile(android::ZipFileRO::open(apkPath));
#define open ___xxx_unix_open
    if (zipFile == nullptr) {
        printf("Could not open %s", apkPath);
        exit(1);
    }
    void* cookie;
    if (zipFile->startIteration(&cookie)) {
        android::ZipEntryRO entry;
        while ((entry = zipFile->nextEntry(cookie)) != NULL) {
            char fileName[256];
            // Make sure we have a file name.
            // TODO: Handle filenames longer than 256.
            if (zipFile->getEntryFileName(entry, fileName, sizeof(fileName))) {
                continue;
            }

            uint32_t uncompressedSize, compressedSize, crc32;
            int64_t dataOffset;
            zipFile->getEntryInfo(entry, nullptr, &uncompressedSize, &compressedSize, &dataOffset,
                                  nullptr, &crc32);
            APKEntry* apkEntry = apkMetaData.add_entries();
            apkEntry->set_crc32(crc32);
            apkEntry->set_filename(fileName);
            apkEntry->set_compressedsize(compressedSize);
            apkEntry->set_dataoffset(dataOffset);
        }
    }
    return apkMetaData;
}

void PatchUtils::WriteSignature(borrowed_fd output) {
    WriteFdExactly(output, kSignature, sizeof(kSignature) - 1);
}

void PatchUtils::WriteLong(int64_t value, borrowed_fd output) {
    int64_t littleEndian = htole64(value);
    WriteFdExactly(output, &littleEndian, sizeof(littleEndian));
}

void PatchUtils::WriteString(const std::string& value, android::base::borrowed_fd output) {
    WriteLong(value.size(), output);
    WriteFdExactly(output, value);
}

void PatchUtils::Pipe(borrowed_fd input, borrowed_fd output, size_t amount) {
    constexpr static size_t BUFFER_SIZE = 128 * 1024;
    char buffer[BUFFER_SIZE];
    size_t transferAmount = 0;
    while (transferAmount != amount) {
        auto chunkAmount = std::min(amount - transferAmount, BUFFER_SIZE);
        auto readAmount = adb_read(input, buffer, chunkAmount);
        if (readAmount < 0) {
            fprintf(stderr, "adb: failed to read from input: %s\n", strerror(errno));
            exit(1);
        }
        WriteFdExactly(output, buffer, readAmount);
        transferAmount += readAmount;
    }
}
