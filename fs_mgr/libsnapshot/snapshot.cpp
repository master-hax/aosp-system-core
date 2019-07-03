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

#include <libsnapshot/snapshot.h>

namespace android {
namespace snapshot {

SnapshotManager SnapshotManager::sInstance;

SnapshotManager& SnapshotManager::Instance() {
    return sInstance;
}

bool SnapshotManager::CreateSnapshotDevice(const std::string& name, const std::string& base_device,
                                           uint64_t cow_size, std::string* dev_path,
                                           const std::chrono::milliseconds& timeout_ms) {
    return false;
}

bool SnapshotManager::MapSnapshotDevice(const std::string& name, std::string* dev_path,
                                        const std::chrono::milliseconds& timeout_ms) {
    return false;
}

bool SnapshotManager::InitiateMerge() {
    return false;
}

bool SnapshotManager::HasIncompleteMerge() {
    return false;
}

}  // namespace snapshot
}  // namespace android
