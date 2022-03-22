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
    InitActionFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();
    void invokeActionManager();
    void invokeActionParser();

  private:
    FuzzedDataProvider mFdp;
};

void InitActionFuzzer::invokeActionManager() {
    ActionManager actionManager;
    while (mFdp.remaining_bytes() > 0) {
        auto actionManagerFunction = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    actionManager.QueueBuiltinAction(
                            initActionFuzzerFunc, mFdp.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() {
                    actionManager.QueueBuiltinAction(
                            SetMmapRndBitsAction, mFdp.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() {
                    actionManager.QueueBuiltinAction(
                            SetKptrRestrictAction,
                            mFdp.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() {
                    actionManager.QueueBuiltinAction(
                            TestPerfEventSelinuxAction,
                            mFdp.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() {
                    actionManager.QueuePropertyChange(
                            mFdp.ConsumeRandomLengthString(kMaxStringLength),
                            mFdp.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() {
                    actionManager.QueueEventTrigger(
                            mFdp.ConsumeRandomLengthString(kMaxStringLength));
                },
                [&]() { actionManager.ExecuteOneCommand(); },
        });
        actionManagerFunction();
    }
}

void InitActionFuzzer::invokeActionParser() {
    BuiltinFunctionMap test_function_map;
    std::string validActionCommand = mFdp.ConsumeBool()
                                             ? kValidActionCommand
                                             : mFdp.ConsumeRandomLengthString(kMaxStringLength);
    if (mFdp.ConsumeBool()) {
        test_function_map = {
                {validActionCommand, {0, 0, {mFdp.ConsumeBool(), initActionFuzzerFunc}}},
        };
    } else {
        test_function_map = {
                {validActionCommand,
                 {mFdp.ConsumeIntegral<size_t>(),
                  mFdp.ConsumeIntegral<size_t>(),
                  {mFdp.ConsumeBool(), initActionFuzzerFunc}}},
        };
    }
    Action::set_function_map(&test_function_map);

    ActionManager actionManager;
    ActionParser actionParser(&actionManager, nullptr);

    std::vector<std::string> args;
    mFdp.ConsumeBool() ? args.push_back(kValidAction)
                       : args.push_back(mFdp.ConsumeRandomLengthString(kMaxStringLength));
    std::string validActionTrigger = mFdp.ConsumeBool()
                                             ? kValidActionTrigger
                                             : mFdp.ConsumeRandomLengthString(kMaxStringLength);
    args.push_back(validActionTrigger);
    if (mFdp.ConsumeBool()) {
        args.push_back(mFdp.ConsumeBool() ? kValidPropertyTrigger
                                          : mFdp.ConsumeRandomLengthString());
        args.push_back(mFdp.ConsumeBool() ? kValidProperty : mFdp.ConsumeRandomLengthString());
    }
    std::string filename = mFdp.PickValueInArray(kValidFilePrefix) +
                           mFdp.ConsumeRandomLengthString(kMaxStringLength);
    int32_t line = mFdp.ConsumeIntegral<int32_t>();
    while (mFdp.remaining_bytes() > 0) {
        auto actionParserFunction = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    if ((actionParser.ParseSection(std::move(args), filename, line)).ok()) {
                        actionParser.ParseLineSection({validActionCommand}, line);
                        actionParser.EndSection();
                    }
                },
                [&]() { actionManager.QueueEventTrigger(validActionTrigger); },
                [&]() { actionManager.ExecuteOneCommand(); },
        });
        actionParserFunction();
    }
}

void InitActionFuzzer::process() {
    mFdp.ConsumeBool() ? invokeActionManager() : invokeActionParser();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitActionFuzzer initActionFuzzer(data, size);
    initActionFuzzer.process();
    return 0;
}
