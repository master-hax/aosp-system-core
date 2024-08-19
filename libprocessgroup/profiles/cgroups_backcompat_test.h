/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <iostream>
#include <string>

#include <gtest/gtest.h>

#include <jsonpb/json_schema_test.h>

#include "../util/internal.h"

namespace android {
namespace profiles {

class CgroupsBackcompatTest : public jsonpb::JsonSchemaTest {};

TEST_P(CgroupsBackcompatTest, ReadDescriptorsFromFileSuccess) {
    auto&& config = ::testing::TestWithParam<jsonpb::JsonSchemaTestConfigFactory>::GetParam()();
    CgroupDescriptorMap descriptors;
    ASSERT_TRUE(ReadDescriptorsFromFile(config->file_path(), &descriptors));
}

}  // namespace profiles
}  // namespace android
