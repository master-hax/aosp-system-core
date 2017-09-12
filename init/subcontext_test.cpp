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

#include <unistd.h>

#include <chrono>

#include <android-base/properties.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>

#include "test_function_map.h"

using namespace std::literals;

using android::base::GetProperty;
using android::base::Join;
using android::base::SetProperty;
using android::base::Split;
using android::base::WaitForProperty;

namespace android {
namespace init {

TEST(subcontext, CheckDifferentPid) {
    TestFunctionMap test_function_map;
    test_function_map.Add("return_pids_as_error", 0, 0, true,
                          [](const std::vector<std::string>& args) -> Result<Success> {
                              return Error() << getpid() << " " << getppid();
                          });
    subcontext_function_map = &test_function_map;

    auto subcontext = Subcontext("path", "u:object_r:init:s0");

    auto result = subcontext.Execute(std::vector<std::string>{"return_pids_as_error"});
    ASSERT_FALSE(result);

    auto pids = Split(result.error_string(), " ");
    ASSERT_EQ(2U, pids.size());
    auto our_pid = std::to_string(getpid());
    EXPECT_NE(our_pid, pids[0]);
    EXPECT_EQ(our_pid, pids[1]);
}

TEST(subcontext, SetProp) {
    TestFunctionMap test_function_map;
    test_function_map.Add("setprop", 2, 2, true, [](const std::vector<std::string>& args) {
        android::base::SetProperty(args[1], args[2]);
        return Success();
    });
    subcontext_function_map = &test_function_map;

    auto subcontext = Subcontext("path", "u:object_r:init:s0");

    SetProperty("init.test.subcontext", "fail");
    WaitForProperty("init.test.subcontext", "fail");

    auto args = std::vector<std::string>{
        "setprop",
        "init.test.subcontext",
        "success",
    };
    auto result = subcontext.Execute(args);
    ASSERT_TRUE(result) << result.error();

    EXPECT_TRUE(WaitForProperty("init.test.subcontext", "success", 10s));
}

TEST(subcontext, MultipleCommands) {
    TestFunctionMap test_function_map;
    auto words = std::vector<std::string>();
    test_function_map.Add("add_word", 1, 1, true, [&words](const std::vector<std::string>& args) {
        words.emplace_back(args[1]);
        return Success();
    });
    test_function_map.Add("return_words_as_error", 0, 0, true,
                          [&words](const std::vector<std::string>& args) -> Result<Success> {
                              return Error() << Join(words, " ");
                          });

    subcontext_function_map = &test_function_map;

    auto subcontext = Subcontext("path", "u:object_r:init:s0");

    auto first_pid = subcontext.pid();

    auto add_word = [&](const auto& word) {
        auto args = std::vector<std::string>{
            "add_word",
            word,
        };
        auto result = subcontext.Execute(args);
        ASSERT_TRUE(result) << result.error();
    };

    auto expected_words = std::vector<std::string>{
        "this",
        "is",
        "a",
        "test",
    };

    for (const auto& word : expected_words) {
        add_word(word);
    }

    auto result = subcontext.Execute(std::vector<std::string>{"return_words_as_error"});
    ASSERT_FALSE(result);
    EXPECT_EQ(Join(expected_words, " "), result.error_string());
    EXPECT_EQ(first_pid, subcontext.pid());
}

TEST(subcontext, RecoverAfterAbort) {
    TestFunctionMap test_function_map;
    test_function_map.Add("cause_log_fatal", 0, 0, true,
                          [](const std::vector<std::string>& args) -> Result<Success> {
                              return Error() << std::string(4097, 'f');
                          });
    test_function_map.Add("generate_sane_error", 0, 0, true,
                          [](const std::vector<std::string>& args) -> Result<Success> {
                              return Error() << "Sane error!";
                          });

    subcontext_function_map = &test_function_map;

    auto subcontext = Subcontext("path", "u:object_r:init:s0");

    auto first_pid = subcontext.pid();

    auto result = subcontext.Execute(std::vector<std::string>{"cause_log_fatal"});
    ASSERT_FALSE(result);

    auto result2 = subcontext.Execute(std::vector<std::string>{"generate_sane_error"});
    ASSERT_FALSE(result2);
    EXPECT_EQ("Sane error!", result2.error_string());
    EXPECT_NE(subcontext.pid(), first_pid);
}

}  // namespace init
}  // namespace android
