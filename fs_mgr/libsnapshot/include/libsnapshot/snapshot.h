// Copyright (C) 2019 The Android Open Source Project
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
#include <memory>
#include <string>

namespace android {
namespace snapshot {

enum class MergeStatus {
    // No update or merge is in progress.
    None,

    // The kernel is merging in the background.
    InProgress,

    // Merging is complete, and needs to be acknowledged.
    Completed
};

class SnapshotManager final {
  public:
    // Return a new SnapshotManager instance, or null on error.
    static std::unique_ptr<SnapshotManager> New();

    // Create a new snapshot device with the given name, base device, and COW device
    // size. The new device path will be returned in |dev_path|. If timeout_ms is
    // greater than zero, this function will wait the given amount of time for
    // |dev_path| to become available, and fail otherwise. If timeout_ms is 0, then
    // no wait will occur and |dev_path| may not yet exist on return.
    bool CreateSnapshot(const std::string& name, const std::string& base_device, uint64_t cow_size,
                        std::string* dev_path, const std::chrono::milliseconds& timeout_ms);

    // Map a snapshot device that was previously created with CreateSnapshot.
    // If a merge was previously initiated, the device-mapper table will have a
    // snapshot-merge target instead of a snapshot target. The timeout parameter
    // is the same as in CreateSnapshotDevice.
    bool MapSnapshotDevice(const std::string& name, const std::string& base_device,
                           const std::chrono::milliseconds& timeout_ms, std::string* dev_path);

    // Unmap a snapshot device previously mapped with MapSnapshotDevice().
    bool UnmapSnapshotDevice(const std::string& name);

    // Remove the backing copy-on-write image for the named snapshot. If the
    // device is still mapped, this will attempt an Unmap, and fail if the
    // unmap fails.
    bool DeleteSnapshot(const std::string& name);

    // Initiate a merge on all snapshot devices. This should only be used after an
    // update has been marked successful after booting.
    bool InitiateMerge();

    // Find the status of the current merge, if any.
    MergeStatus GetMergeStatus();

    // Clean up device-mapper state after a merge is done. This MUST be called
    // if GetMergeStatus == Completed, and must not be called under any other
    // circumstance.
    bool ProcessCompletedMerge();
};

}  // namespace snapshot
}  // namespace android
