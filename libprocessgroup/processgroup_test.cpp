/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <unistd.h>
#include "task_profiles.h"

namespace {

TEST(SetProcessProfiles, SetProcessProfiles) {
    TaskProfiles* tp = &TaskProfiles::GetInstance();
    tp->LoadFromString(CgroupMap::GetInstance(), R"json(
{
    "Profiles" : [
        {
            "Name" : "profile_1",
        },
        {
            "Name" : "profile_2",
        },
        {
            "Name" : "profile_3",
        },
        {
            "Name" : "profile_4",
        },
        {
            "Name" : "profile_5",
        },
    ],
}
                      )json");

    int count;
    std::function<bool(TaskProfile*, uid_t, pid_t)> cb =
        [&count](TaskProfile* tp, uid_t uid, pid_t pid) { count++; return true;};
    std::array<std::string_view, 5> profile_array{"profile_1", "profile_2", "profile_3",
                                                  "profile_4", "profile_5"};
    std::span<std::string_view> profiles = profile_array;

    count = 0;
    EXPECT_TRUE(tp->SetProcessProfiles(getuid(), getpid(), profiles.first(0), cb, false));
    EXPECT_EQ(count, 0);
    EXPECT_TRUE(tp->SetProcessProfiles(getuid(), getpid(), profiles.first(1), cb, false));
    EXPECT_EQ(count, 1);
    count = 0;
    EXPECT_TRUE(tp->SetProcessProfiles(getuid(), getpid(), profiles.first(4), cb, false));
    EXPECT_EQ(count, 4);
    count = 0;
    EXPECT_TRUE(tp->SetProcessProfiles(getuid(), getpid(), profiles.first(5), cb, false));
    EXPECT_EQ(count, 5);
}

}  // namespace
