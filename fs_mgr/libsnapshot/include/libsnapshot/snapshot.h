// Copyright (C) 2018 The Android Open Source Project
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

#include <stdint.h>

#include <chrono>
#include <string>

namespace android {
namespace snapshot {

class SnapshotManager final {
  public:
    SnapshotManager& Instance();

    // Create a new snapshot device with the given name, base device, and COW device
    // size. The new device path will be returned in |dev_path|. If the device is not
    // available after |timeout_ms|, and timeout_ms is greater than 0, this function
    // will return false.
    bool CreateSnapshotDevice(const std::string& name, const std::string& base_device,
                              uint64_t cow_size, std::string* dev_path,
                              const std::chrono::milliseconds& timeout_ms);

    // Map a snapshot device that was previously created with CreateSnapshotDevice.
    // If a merge was previously initiated, the device-mapper table will have a
    // snapshot-merge target instead of a snapshot target.
    bool MapSnapshotDevice(const std::string& name, std::string* dev_path,
                           const std::chrono::milliseconds& timeout_ms);

    // Initiate a merge on all snapshot devices. This should only be used after an
    // update has been marked successful after booting.
    bool InitiateMerge();

    // Return whether or not a merge is in progress. This returns true if a merge
    // was ever started, whether or not a snapshot-merge target is currently
    // loaded. For example, this will return true in recovery when system/vendor/etc
    // are not mounted.
    bool HasIncompleteMerge();

  private:
    static SnapshotManager sInstance;
};

}  // namespace snapshot
}  // namespace android
