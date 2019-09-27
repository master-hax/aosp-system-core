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

#include <gmock/gmock.h>

#include <liblp/partition_properties.h>

namespace android {
namespace fs_mgr {
namespace testing {

class MockPartitionProperties : public IPartitionProperties {
  public:
    MOCK_METHOD0(IsAb, bool());
    MOCK_METHOD0(IsRetrofitDynamicPartitions, bool());
    MOCK_METHOD0(IsVirtualAb, bool());
};

}  // namespace testing
}  // namespace fs_mgr
}  // namespace android

