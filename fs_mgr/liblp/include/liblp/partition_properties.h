//
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
//

#pragma once

namespace android {
namespace fs_mgr {

class IPartitionProperties {
  public:
    virtual ~IPartitionProperties() = default;

    // Returns true if this is an A/B device.
    virtual bool IsAb() const = 0;

    // Returns true if this device retrofits dynamic partitions.
    virtual bool IsRetrofitDynamicPartitions() const = 0;

    // Returns true if this device has Virtual A/B (launch or retrofit).
    virtual bool IsVirtualAb() const = 0;
};

// Helper class to implement IPartitionProperties.
class PartitionProperties : public IPartitionProperties {
    bool IsAb() const override;
    bool IsRetrofitDynamicPartitions() const override;
    bool IsVirtualAb() const override;
};

}  // namespace fs_mgr
}  // namespace android
