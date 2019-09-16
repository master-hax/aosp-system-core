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

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <adb_unique_fd.h>
#include "fastdeploy/proto/ApkEntry.pb.h"

class ApkArchiveTester;

// Manipulates an APK archive. Process it by mmaping it in order to minimize
// I/Os.
class ApkArchive {
  public:
    friend ApkArchiveTester;

    // A convenience struct to store the result of search operation when
    // locating the EoCDr, CDr, and Signature Block.
    struct Location {
        size_t offset = 0;
        size_t size = 0;
        bool valid = false;
    };

    ApkArchive(const std::string& path);
    ~ApkArchive();

    com::android::fastdeploy::APKDump ExtractMetadata();

    // Parses the CDr starting from |input| and returns number of bytes consumed.
    // Extracts local file header offset and calculates MD5 hash of the record.
    // 0 indicates invalid CDr.
    static size_t ParseCentralDirectoryRecord(const char* input, size_t size, std::string* md5Hash,
                                              int64_t* localFileHeaderOffset);
    // Calculates Local File Entry size including header.
    // 0 indicates invalid Local File Entry.
    size_t CalculateLocalFileEntrySize(int64_t localFileHeaderOffset) const;

  private:
    std::string ReadMetadata(Location loc) const;

    // Retrieve the location of the Central Directory Record.
    Location GetCDLocation();

    // Retrieve the location of the signature block starting from Central
    // Directory Record
    Location GetSignatureLocation(size_t offset_to_cdrecord);
    size_t GetArchiveSize() const;

    // Find the End of Central Directory Record, starting from the end of the
    // file.
    uint8_t* FindEndOfCDRecord() const;

    // Find Central Directory Record, starting from the end of the file.
    Location FindCDRecord(const uint8_t* cursor);

    // Open apk and mmap it.
    void Prepare();

    // Checks if the archive can be used.
    bool ready() const { return fd_ >= 0; }

    std::string path_;
    uint8_t* start_;
    size_t size_;
    unique_fd fd_;
};
