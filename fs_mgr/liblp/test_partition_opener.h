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

#pragma once

#include <map>
#include <string>

#include <android-base/unique_fd.h>
#include <liblp/partition_opener.h>

namespace android {
namespace fs_mgr {

class TestPartitionProperties : public IPartitionProperties {
   public:
    bool IsAb() const override {
        return ab;
    }

    bool IsRetrofitDynamicPartitions() const override {
        return retrofit_dap;
    }

    bool IsVirtualAb() const override {
        return vab;
    }

    bool ab = false;
    bool retrofit_dap = false;
    bool vab = false;
};

class TestPartitionOpener : public PartitionOpener {
  public:
    explicit TestPartitionOpener(const std::map<std::string, int>& partition_map = {},
                                 const std::map<std::string, BlockDeviceInfo>& partition_info = {},
                                 const TestPartitionProperties& properties = {});

    android::base::unique_fd Open(const std::string& partition_name, int flags) const override;
    bool GetInfo(const std::string& partition_name, BlockDeviceInfo* info) const override;
    std::unique_ptr<IPartitionProperties> GetProperties() const override {
        return std::make_unique<TestPartitionProperties>(properties_);
    }

  private:
    std::map<std::string, int> partition_map_;
    std::map<std::string, BlockDeviceInfo> partition_info_;
    TestPartitionProperties properties_;
};

}  // namespace fs_mgr
}  // namespace android
