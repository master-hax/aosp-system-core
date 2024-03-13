// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

namespace android {
namespace snapshot {

const std::string kMkF2fs = "/system/bin/make_f2fs";
const std::string kMkExt4 = "/system/bin/mke2fs";

const std::string kOtaFileContext = "u:object_r:ota_metadata_file:s0";
const std::string kScratchMount = "/mnt/scratch_super";

constexpr char kPhysicalDevice[] = "/dev/block/by-name/";

bool SetupOTADirs();
bool MountScratch(const std::string& device_path);
bool MakeScratchFilesystem(const std::string& scratch_device);
bool CreateDynamicScratch(std::string* scratch_device, size_t size, int slot);
bool CleanupScratch();
bool IsScratchPresent();
std::string GetScratchDevice();
std::string MapScratchDevice(std::string device);

}  // namespace snapshot
}  // namespace android
