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

#include "deploy_patch_generator.h"

#include <inttypes.h>
#include <stdio.h>

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

#include "adb_unique_fd.h"
#include "android-base/file.h"
#include "patch_utils.h"
#include "sysdeps.h"

using namespace com::android::fastdeploy;

void DeployPatchGenerator::Log(const char* fmt, ...) {
    if (!is_verbose_) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

void DeployPatchGenerator::APKEntryToLog(const APKEntry& entry) {
    Log("Filename: %s", entry.filename().c_str());
    Log("CRC32: 0x%08" PRIX64, entry.crc32());
    Log("Data Offset: %" PRId64, entry.dataoffset());
    Log("Compressed Size: %" PRId64, entry.compressedsize());
    Log("Uncompressed Size: %" PRId64, entry.uncompressedsize());
}

void DeployPatchGenerator::APKMetaDataToLog(const APKMetaData& metadata) {
    if (!is_verbose_) {
        return;
    }
    Log("APK Metadata: %s", metadata.absolute_path().c_str());
    for (int i = 0; i < metadata.entries_size(); i++) {
        const APKEntry& entry = metadata.entries(i);
        APKEntryToLog(entry);
    }
}

void DeployPatchGenerator::ReportSavings(const std::vector<SimpleEntry>& identicalEntries,
                                         uint64_t totalSize) {
    long totalEqualBytes = 0;
    int totalEqualFiles = 0;
    for (size_t i = 0; i < identicalEntries.size(); i++) {
        if (identicalEntries[i].deviceEntry != nullptr) {
            totalEqualBytes += identicalEntries[i].localEntry->compressedsize();
            totalEqualFiles++;
        }
    }
    float savingPercent = (totalEqualBytes * 100.0f) / totalSize;
    fprintf(stderr, "Detected %d equal APK entries\n", totalEqualFiles);
    fprintf(stderr, "%ld bytes are equal out of %" PRIu64 " (%.2f%%)\n", totalEqualBytes, totalSize,
            savingPercent);
}

void DeployPatchGenerator::GeneratePatch(const std::vector<SimpleEntry>& entriesToUseOnDevice,
                                         const std::string& localApkPath,
                                         const std::string& deviceApkPath, borrowed_fd output) {
    unique_fd input(adb_open(localApkPath.c_str(), O_RDONLY | O_CLOEXEC));
    size_t newApkSize = adb_lseek(input, 0L, SEEK_END);
    adb_lseek(input, 0L, SEEK_SET);

    // Header.
    PatchUtils::WriteSignature(output);
    PatchUtils::WriteLong(newApkSize, output);

    PatchUtils::WriteString(deviceApkPath, output);
    size_t currentSizeOut = 0;
    // Write data from the host upto the first entry we have that matches a device entry. Then write
    // the metadata about the device entry and repeat for all entries that match on device. Finally
    // write out any data left. If the device and host APKs are exactly the same this ends up
    // writing out zip metadata from the local APK followed by offsets to the data to use from the
    // device APK.
    for (size_t i = 0, size = entriesToUseOnDevice.size(); i < size; ++i) {
        auto&& entry = entriesToUseOnDevice[i];
        int64_t hostDataOffset = entry.localEntry->dataoffset();
        int64_t deltaFromDeviceDataStart = hostDataOffset - currentSizeOut;
        PatchUtils::WriteLong(deltaFromDeviceDataStart, output);
        if (deltaFromDeviceDataStart > 0) {
            PatchUtils::Pipe(input, output, deltaFromDeviceDataStart);
        }
        int64_t deviceDataLength = entry.deviceEntry->compressedsize();
        int64_t deviceLFHOffset = entry.deviceEntry->dataoffset();
        PatchUtils::WriteLong(deviceLFHOffset, output);
        adb_lseek(input, deviceDataLength, SEEK_CUR);
        currentSizeOut += deltaFromDeviceDataStart + deviceDataLength;
    }
    if (newApkSize > currentSizeOut) {
        PatchUtils::WriteLong(newApkSize - currentSizeOut, output);
        PatchUtils::Pipe(input, output, newApkSize - currentSizeOut);
        PatchUtils::WriteLong(-1, output);  // Invalid LFH offset.
    }
}

bool DeployPatchGenerator::CreatePatch(const char* localApkPath, APKMetaData deviceApkMetadata,
                                       android::base::borrowed_fd output) {
    return CreatePatch(PatchUtils::GetAPKMetaData(localApkPath), std::move(deviceApkMetadata),
                       output);
}

bool DeployPatchGenerator::CreatePatch(APKMetaData localApkMetadata, APKMetaData deviceApkMetadata,
                                       borrowed_fd output) {
    // Log metadata info.
    APKMetaDataToLog(deviceApkMetadata);
    APKMetaDataToLog(localApkMetadata);

    const std::string localApkPath = localApkMetadata.absolute_path();
    const std::string deviceApkPath = deviceApkMetadata.absolute_path();

    std::vector<SimpleEntry> identicalEntries;
    uint64_t totalSize = BuildIdenticalEntries(identicalEntries, std::move(localApkMetadata),
                                               std::move(deviceApkMetadata));
    ReportSavings(identicalEntries, totalSize);
    GeneratePatch(identicalEntries, localApkPath, deviceApkPath, output);

    return true;
}

uint64_t DeployPatchGenerator::BuildIdenticalEntries(std::vector<SimpleEntry>& outIdenticalEntries,
                                                     APKMetaData localApkMetadata,
                                                     APKMetaData deviceApkMetadata) {
    std::unordered_map<int, std::vector<const APKEntry*>> deviceEntries;
    for (const auto& deviceEntry : deviceApkMetadata.entries()) {
        deviceEntries[deviceEntry.crc32()].push_back(&deviceEntry);
    }

    uint64_t totalSize = 0;
    for (const auto& localEntry : localApkMetadata.entries()) {
        totalSize += localEntry.compressedsize();
        for (const auto* deviceEntry : deviceEntries[localEntry.crc32()]) {
            if (deviceEntry->filename() == localEntry.filename()) {
                SimpleEntry simpleEntry;
                simpleEntry.localEntry = &localEntry;
                simpleEntry.deviceEntry = deviceEntry;
                APKEntryToLog(localEntry);
                outIdenticalEntries.push_back(simpleEntry);
                break;
            }
        }
    }
    std::sort(outIdenticalEntries.begin(), outIdenticalEntries.end(),
              [](const SimpleEntry& lhs, const SimpleEntry& rhs) {
                  return lhs.localEntry->dataoffset() < rhs.localEntry->dataoffset();
              });
    return totalSize;
}
