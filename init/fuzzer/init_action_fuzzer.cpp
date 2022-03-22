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

#include <action_manager.h>
#include <action_parser.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <parser.h>
#include <security.h>
#include <subcontext.h>
#include <sys/wait.h>
#include <utils/Log.h>

using namespace android::init;

constexpr size_t kMaxStringLength = 20;
const std::string kValidFilePrefix[] = {"/vendor", "/odm"};
const std::string kValidProperty = "property:init.svc.vendor.charger=running";
const std::string kValidActionTrigger = "boot";
const std::string kValidAction = "on";
const std::string kValidActionCommand = "FUZZER_ACTION";
const std::string kValidPropertyTrigger = "&&";

Result<void> initActionFuzzerFunc(const BuiltinArguments&) {
    return {};
}

class InitActionFuzzer {
  public:
    InitActionFuzzer(const uint8_t* data, size_t size) : fdp_(data, size){};
    void Process();
    void InvokeActionManager();
    void InvokeActionParser();

  private:
    FuzzedDataProvider fdp_;
};

void InitActionFuzzer::InvokeActionManager() {
    ActionManager action_manager;
    while (fdp_.remaining_bytes() > 0) {
        auto action_manager_function = fdp_.PickValueInArray<const std::function<void()>>({
                [&]() {
                    action_manager.QueueBuiltinAction(
                            initActionFuzzerFunc, fdp_.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() {
                    action_manager.QueueBuiltinAction(
                            SetMmapRndBitsAction, fdp_.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() {
                    action_manager.QueueBuiltinAction(
                            SetKptrRestrictAction,
                            fdp_.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() {
                    action_manager.QueueBuiltinAction(
                            TestPerfEventSelinuxAction,
                            fdp_.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() {
                    action_manager.QueuePropertyChange(
                            fdp_.ConsumeRandomLengthString(kMaxStringLength),
                            fdp_.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() {
                    action_manager.QueueEventTrigger(
                            fdp_.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() { action_manager.ExecuteOneCommand(); },
        });
        action_manager_function();
    }
}

void InitActionFuzzer::InvokeActionParser() {
    BuiltinFunctionMap test_function_map;
    std::string valid_action_command = fdp_.ConsumeBool()
                                               ? kValidActionCommand
                                               : fdp_.ConsumeRandomLengthString(kMaxStringLength);
    if (fdp_.ConsumeBool()) {
        test_function_map = {
                {valid_action_command, {0, 0, {fdp_.ConsumeBool(), initActionFuzzerFunc}}},
        };
    } else {
        test_function_map = {
                {valid_action_command,
                 {fdp_.ConsumeIntegral<size_t>(),
                  fdp_.ConsumeIntegral<size_t>(),
                  {fdp_.ConsumeBool(), initActionFuzzerFunc}}},
        };
    }
    Action::set_function_map(&test_function_map);

    ActionManager action_manager;
    ActionParser action_parser(&action_manager, nullptr);

    std::vector<std::string> args;
    fdp_.ConsumeBool() ? args.push_back(kValidAction)
                       : args.push_back(fdp_.ConsumeRandomLengthString(kMaxStringLength));
    std::string valid_action_trigger = fdp_.ConsumeBool()
                                               ? kValidActionTrigger
                                               : fdp_.ConsumeRandomLengthString(kMaxStringLength);
    args.push_back(valid_action_trigger);
    if (fdp_.ConsumeBool()) {
        args.push_back(fdp_.ConsumeBool() ? kValidPropertyTrigger
                                          : fdp_.ConsumeRandomLengthString());
        args.push_back(fdp_.ConsumeBool() ? kValidProperty : fdp_.ConsumeRandomLengthString());
    }
    std::string filename = fdp_.PickValueInArray(kValidFilePrefix) +
                           fdp_.ConsumeRandomLengthString(kMaxStringLength);
    int32_t line = fdp_.ConsumeIntegral<int32_t>();
    while (fdp_.remaining_bytes() > 0) {
        auto action_parser_function = fdp_.PickValueInArray<const std::function<void()>>({
                [&]() {
                    if ((action_parser.ParseSection(std::move(args), filename, line)).ok()) {
                        action_parser.ParseLineSection({valid_action_command}, line);
                        action_parser.EndSection();
                    }
                },
                [&]() { action_manager.QueueEventTrigger(valid_action_trigger); },
                [&]() { action_manager.ExecuteOneCommand(); },
        });
        action_parser_function();
    }
}

void InitActionFuzzer::Process() {
    fdp_.ConsumeBool() ? InvokeActionManager() : InvokeActionParser();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitActionFuzzer initActionFuzzer(data, size);
    initActionFuzzer.Process();
    return 0;
}
