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
#include <selinux/selinux.h>

#include "builtin_arguments.h"
#include "util.h"

using namespace std::literals;

using android::base::GetProperty;
using android::base::Join;
using android::base::SetProperty;
using android::base::Split;
using android::base::WaitForProperty;

namespace android {
namespace init {

void RunTest(std::function<void(Subcontext&)>&& test_function, std::string test_context) {
    Subcontext subcontext = Subcontext({"dummy_path"}, test_context);
    ASSERT_NE(0, subcontext.pid());

    test_function(subcontext);

    if (subcontext.pid() > 0) {
        kill(subcontext.pid(), SIGTERM);
        kill(subcontext.pid(), SIGKILL);
    }
}

TEST(subcontext, CheckDifferentPid) {
    RunTest(
            [](Subcontext& subcontext) {
                Result<void> result =
                        subcontext.Execute(std::vector<std::string>{"return_pids_as_error"});
                ASSERT_FALSE(result.ok());

                std::vector<std::string> pids = Split(result.error().message(), " ");
                ASSERT_EQ(2U, pids.size());
                std::string our_pid = std::to_string(getpid());
                EXPECT_NE(our_pid, pids[0]);
                EXPECT_EQ(our_pid, pids[1]);
            },
            kTestContext);
}

TEST(subcontext, SetProp) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Skipping test, must be run as root.";
        return;
    }

    RunTest(
            [](Subcontext& subcontext) {
                SetProperty("init.test.subcontext", "fail");
                WaitForProperty("init.test.subcontext", "fail");

                std::vector<std::string> args{
                        "setprop",
                        "init.test.subcontext",
                        "success",
                };
                Result<void> result = subcontext.Execute(args);
                ASSERT_RESULT_OK(result);

                EXPECT_TRUE(WaitForProperty("init.test.subcontext", "success", 10s));
            },
            kTestContext);
}

TEST(subcontext, MultipleCommands) {
    RunTest(
            [](Subcontext& subcontext) {
                pid_t first_pid = subcontext.pid();

                std::vector<std::string> expected_words{
                        "this",
                        "is",
                        "a",
                        "test",
                };

                for (const std::string& word : expected_words) {
                    std::vector<std::string> args{
                            "add_word",
                            word,
                    };
                    Result<void> result = subcontext.Execute(args);
                    ASSERT_RESULT_OK(result);
                }

                Result<void> result =
                        subcontext.Execute(std::vector<std::string>{"return_words_as_error"});
                ASSERT_FALSE(result.ok());
                EXPECT_EQ(Join(expected_words, " "), result.error().message());
                EXPECT_EQ(first_pid, subcontext.pid());
            },
            kTestContext);
}

TEST(subcontext, RecoverAfterAbort) {
    RunTest(
            [](Subcontext& subcontext) {
                pid_t first_pid = subcontext.pid();

                Result<void> result =
                        subcontext.Execute(std::vector<std::string>{"cause_log_fatal"});
                ASSERT_FALSE(result.ok());

                Result<void> result2 =
                        subcontext.Execute(std::vector<std::string>{"generate_sane_error"});
                ASSERT_FALSE(result2.ok());
                EXPECT_EQ("Sane error!", result2.error().message());
                EXPECT_NE(subcontext.pid(), first_pid);
            },
            kTestContext);
}

TEST(subcontext, ContextString) {
    RunTest(
            [](Subcontext& subcontext) {
                Result<void> result =
                        subcontext.Execute(std::vector<std::string>{"return_context_as_error"});
                ASSERT_FALSE(result.ok());
                ASSERT_EQ(kTestContext, result.error().message());
            },
            kTestContext);
}

TEST(subcontext, TriggerShutdown) {
    static constexpr const char kTestShutdownCommand[] = "reboot,test-shutdown-command";
    static std::string trigger_shutdown_command;
    trigger_shutdown = [](const std::string& command) { trigger_shutdown_command = command; };
    RunTest(
            [](Subcontext& subcontext) {
                Result<void> result = subcontext.Execute(
                        std::vector<std::string>{"trigger_shutdown", kTestShutdownCommand});
                ASSERT_RESULT_OK(result);
            },
            kTestContext);
    EXPECT_EQ(kTestShutdownCommand, trigger_shutdown_command);
}

TEST(subcontext, ExpandArgs) {
    RunTest(
            [](Subcontext& subcontext) {
                std::vector<std::string> args{
                        "first",
                        "${ro.hardware}",
                        "$$third",
                };
                Result<std::vector<std::string>> result = subcontext.ExpandArgs(args);
                ASSERT_RESULT_OK(result);
                ASSERT_EQ(3U, result->size());
                EXPECT_EQ(args[0], result->at(0));
                EXPECT_EQ(GetProperty("ro.hardware", ""), result->at(1));
                EXPECT_EQ("$third", result->at(2));
            },
            kTestContext);
}

TEST(subcontext, ExpandArgsFailure) {
    RunTest(
            [](Subcontext& subcontext) {
                std::vector<std::string> args{
                        "first",
                        "${",
                };
                Result<std::vector<std::string>> result = subcontext.ExpandArgs(args);
                ASSERT_FALSE(result.ok());
                EXPECT_EQ("unexpected end of string in '" + args[1] + "', looking for }",
                          result.error().message());
            },
            kTestContext);
}

BuiltinFunctionMap BuildTestFunctionMap() {
    // For CheckDifferentPid
    auto do_return_pids_as_error = [](const BuiltinArguments& args) -> Result<void> {
        return Error() << getpid() << " " << getppid();
    };

    // For SetProp
    auto do_setprop = [](const BuiltinArguments& args) {
        android::base::SetProperty(args[1], args[2]);
        return Result<void>{};
    };

    // For MultipleCommands
    // Using a shared_ptr to extend lifetime of words to both lambdas
    auto words = std::make_shared<std::vector<std::string>>();
    auto do_add_word = [words](const BuiltinArguments& args) {
        words->emplace_back(args[1]);
        return Result<void>{};
    };
    auto do_return_words_as_error = [words](const BuiltinArguments& args) -> Result<void> {
        return Error() << Join(*words, " ");
    };

    // For RecoverAfterAbort
    auto do_cause_log_fatal = [](const BuiltinArguments& args) -> Result<void> {
        // Since this is an expected failure, disable debuggerd to not generate a tombstone.
        signal(SIGABRT, SIG_DFL);
        return Error() << std::string(4097, 'f');
    };
    auto do_generate_sane_error = [](const BuiltinArguments& args) -> Result<void> {
        return Error() << "Sane error!";
    };

    // For ContextString
    auto do_return_context_as_error = [](const BuiltinArguments& args) -> Result<void> {
        return Error() << args.context;
    };

    auto do_trigger_shutdown = [](const BuiltinArguments& args) -> Result<void> {
        trigger_shutdown(args[1]);
        return {};
    };

    // clang-format off
    BuiltinFunctionMap test_function_map = {
        {"return_pids_as_error",        {0,     0,      {true,  do_return_pids_as_error}}},
        {"setprop",                     {2,     2,      {true,  do_setprop}}},
        {"add_word",                    {1,     1,      {true,  do_add_word}}},
        {"return_words_as_error",       {0,     0,      {true,  do_return_words_as_error}}},
        {"cause_log_fatal",             {0,     0,      {true,  do_cause_log_fatal}}},
        {"generate_sane_error",         {0,     0,      {true,  do_generate_sane_error}}},
        {"return_context_as_error",     {0,     0,      {true,  do_return_context_as_error}}},
        {"trigger_shutdown",            {1,     1,      {true,  do_trigger_shutdown}}},
    };
    // clang-format on
    return test_function_map;
}

}  // namespace init
}  // namespace android

// init_test.cpp contains the main entry point for all init tests.
int SubcontextTestChildMain(int argc, char** argv) {
    using namespace android::init;

    const BuiltinFunctionMap& test_function_map = BuildTestFunctionMap();
    return SubcontextMain(argc, argv, &test_function_map);
}
