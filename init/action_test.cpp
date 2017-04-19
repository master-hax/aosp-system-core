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

#include "action.h"

#include <functional>

#include <gtest/gtest.h>

#include "builtins.h"
#include "keyword_map.h"

class TestFunctionMap : public KeywordMap<BuiltinFunction> {
  public:
    // Helper for argument-less functions
    using BuiltinFunctionNoArgs = std::function<void(void)>;
    void Add(const std::string& name, const BuiltinFunctionNoArgs function) {
        Add(name, 0, 0, [function](const std::vector<std::string>&) {
            function();
            return 0;
        });
    }

    void Add(const std::string& name, std::size_t min_parameters, std::size_t max_parameters,
             const BuiltinFunction function) {
        builtin_functions_[name] = make_tuple(min_parameters, max_parameters, function);
    }

  private:
    Map builtin_functions_ = {};

    const Map& map() const override { return builtin_functions_; }
};

using ActionManagerCommand = std::function<void(ActionManager&)>;

// Take a init script segment and a function map, parse it, run a set of commands
void TestActionManager(const std::string& init_script, const TestFunctionMap& test_function_map,
                       const std::vector<ActionManagerCommand>& commands) {
    ActionManager am;

    Action::set_function_map(&test_function_map);

    Parser parser;
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&am));

    parser.ParseData("test_file_name", init_script);

    for (const auto& command : commands) {
        command(am);
    }

    while (am.HasMoreCommands()) {
        am.ExecuteOneCommand();
    }
}

TEST(action, EventTrigger) {
    bool expect_true = false;
    std::string init_script =
        R"init(
on boot
pass_test
)init";

    TestFunctionMap test_function_map;
    test_function_map.Add("pass_test", [&expect_true]() { expect_true = true; });

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};

    TestActionManager(init_script, test_function_map, commands);

    EXPECT_TRUE(expect_true);
}

TEST(action, EventTriggerOrder) {
    int num_executed = 0;
    std::string init_script =
        R"init(
on boot
execute_first

on boot && property:ro.hardware=*
execute_second

on boot
execute_third

)init";

    TestFunctionMap test_function_map;
    test_function_map.Add("execute_first", [&num_executed]() { EXPECT_EQ(0, num_executed++); });
    test_function_map.Add("execute_second", [&num_executed]() { EXPECT_EQ(1, num_executed++); });
    test_function_map.Add("execute_third", [&num_executed]() { EXPECT_EQ(2, num_executed++); });

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};

    TestActionManager(init_script, test_function_map, commands);
}
