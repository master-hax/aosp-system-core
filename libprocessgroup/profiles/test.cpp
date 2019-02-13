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

#include <string>

#include <android-base/file.h>
#include <gmock/gmock.h>
#include <jsonpb/json_schema_test.h>

#include "cgroups.pb.h"
#include "task_profiles.pb.h"

using namespace ::android::jsonpb;
using ::android::base::GetExecutableDirectory;
using ::testing::MatchesRegex;

namespace android {
namespace profiles {

template <typename T>
JsonSchemaTestConfigFactory MakeTestParam(const std::string& path) {
    return jsonpb::MakeTestParam<T>(GetExecutableDirectory() + path);
}

INSTANTIATE_TEST_SUITE_P(LibProcessgroupProto, JsonSchemaTest,
                         ::testing::Values(MakeTestParam<Cgroups>("/cgroups.json"),
                                           MakeTestParam<Cgroups>("/cgroups.recovery.json"),
                                           MakeTestParam<TaskProfiles>("/task_profiles.json")));

TEST(LibProcessgroupProto, EmptyMode) {
    EXPECT_EQ(0, strtoul("", nullptr, 8))
            << "Empty mode string cannot be silently converted to 0; this should not happen";
}

class CgroupsTest : public JsonSchemaTest {
  public:
    void SetUp() override {
        JsonSchemaTest::SetUp();
        cgroups_ = static_cast<Cgroups*>(message());
    }
    Cgroups* cgroups_;
};

static constexpr const char* REGEX_MODE = "(0[0-7]{3})?";

// "Mode" field must be in the format of "0xxx".
TEST_P(CgroupsTest, Mode) {
    for (auto&& cgroup : cgroups_->cgroups()) {
        EXPECT_THAT(cgroup.mode(), MatchesRegex(REGEX_MODE))
                << "For cgroup controller " << cgroup.controller();
    }
    EXPECT_THAT(cgroups_->cgroups2().mode(), MatchesRegex(REGEX_MODE)) << "For cgroups2";
}

INSTANTIATE_TEST_SUITE_P(LibProcessgroupProto, CgroupsTest,
                         ::testing::Values(MakeTestParam<Cgroups>("/cgroups.json"),
                                           MakeTestParam<Cgroups>("/cgroups.recovery.json")));

}  // namespace profiles
}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
