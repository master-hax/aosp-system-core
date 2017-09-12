/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "subcontext.h"

#include <chrono>

#include <android-base/properties.h>
#include <gtest/gtest.h>

#include "test_function_map.h"

using namespace std::literals;

using android::base::GetProperty;
using android::base::SetProperty;
using android::base::WaitForProperty;

namespace android {
namespace init {

TEST(subcontext, SetProp) {
    TestFunctionMap test_function_map;
    test_function_map.Add("setprop", 2, 2, true, [](const std::vector<std::string>& args) {
        android::base::SetProperty(args[1], args[2]);
        return Success();
    });
    subcontext_function_map = &test_function_map;

    Subcontext subcontext("u:object_r:init:s0");

    SetProperty("init.test.subcontext", "fail");
    WaitForProperty("init.test.subcontext", "fail");

    std::vector<std::string> args = {
        "setprop",
        "init.test.subcontext",
        "success",
    };
    auto result = subcontext.Execute(args);
    ASSERT_TRUE(result) << result.error();

    EXPECT_TRUE(WaitForProperty("init.test.subcontext", "success", 10s));
}

}  // namespace init
}  // namespace android
