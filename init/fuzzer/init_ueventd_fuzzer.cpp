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

#include <bootchart.h>
#include <fscrypt_init_extensions.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <keyutils.h>
#include <mount_namespace.h>
#include <service_parser.h>
#include <ueventd_parser.h>

#include <android-base/file.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>

using namespace android;
using namespace android::init;

constexpr int32_t kMinRange = 1;
constexpr int32_t kMaxRange = 4;
constexpr int32_t kMinLength = 1;
constexpr int32_t kMaxLength = 100;
constexpr int32_t kMaxBytes = 256;
constexpr int32_t kBootchartMinWaitTime = 0;
constexpr int32_t kBootchartMaxWaitTime = 1000;
const std::string kCheckRC = ".rc";
const std::string kTestScriptPath = "/data/fuzz/fuzzerTest.rc";
const std::string kBootchartEnabledPath = "/data/bootchart/enabled";

const std::string kValidPaths[] = {
        "/data/fuzz",
        "/apex/",
        "/vendor/",
        "/system/",
};

const std::string kFscryptRefPath[] = {
        "/unencrypted/ref",
        "/unencrypted/per_boot_ref",
};

constexpr FscryptAction kAction[] = {
        FscryptAction::kNone,
        FscryptAction::kAttempt,
        FscryptAction::kRequire,
        FscryptAction::kDeleteIfNecessary,
};

constexpr MountNamespace kNamespace[] = {
        MountNamespace::NS_BOOTSTRAP,
        MountNamespace::NS_DEFAULT,
};

class InitUeventDFuzzer {
  public:
    InitUeventDFuzzer(const uint8_t* data, size_t size) : fdp_(data, size) {
        GenerateRandomScript();
        std::filesystem::permissions(kTestScriptPath,
                                     std::filesystem::perms::owner_all |
                                             std::filesystem::perms::group_read |
                                             std::filesystem::perms::others_read,
                                     std::filesystem::perm_options::replace);
    };
    void Process();

  private:
    void CreateBootchartEnabled();
    void InvokeParser(int32_t);
    void ProcessPaths(std::string);
    void GenerateRandomScript();

    FuzzedDataProvider fdp_;
    std::string arch_type_;
    std::string test_script_path_;
    std::vector<std::string> path_data_;
};

void InitUeventDFuzzer::CreateBootchartEnabled() {
    std::ofstream temp_file;
    temp_file.open(kBootchartEnabledPath, std::ios::out | std::ios::binary);
    std::string data = "";
    if (fdp_.ConsumeBool()) {
        data = fdp_.ConsumeRandomLengthString(kMaxBytes);
    }
    temp_file.write(data.c_str(), data.size());
    temp_file.close();
}

void InitUeventDFuzzer::GenerateRandomScript() {
    std::ofstream temp_file;
    temp_file.open(kTestScriptPath, std::ios::out | std::ios::binary);
    std::string data = "";
    for (size_t idx = 0; idx < fdp_.ConsumeIntegralInRange<size_t>(kMinLength, kMaxLength); ++idx) {
        data = fdp_.ConsumeRandomLengthString(kMaxBytes) + "\n";
    }
    temp_file.write(data.c_str(), data.size());
    temp_file.close();
}

void InitUeventDFuzzer::ProcessPaths(std::string dirPath) {
    for (auto const& dir_entry : std::filesystem::recursive_directory_iterator(dirPath)) {
        std::string sub_path = dir_entry.path();
        if (sub_path.compare(sub_path.size() - kCheckRC.size(), kCheckRC.size(), kCheckRC) == 0) {
            path_data_.push_back(sub_path);
        }
    }
}

void InitUeventDFuzzer::InvokeParser(int32_t choice) {
    TemporaryFile tf;
    Parser parser;
    std::string parser_name =
            fdp_.ConsumeBool() ? "service" : fdp_.ConsumeRandomLengthString(kMaxBytes);
    parser.AddSectionParser(
            parser_name,
            std::make_unique<ServiceParser>(&(ServiceList::GetInstance()), GetSubcontext(),
                                            std::nullopt /* interface_inheritance_hierarchy */));
    switch (choice) {
        case 1:
            parser.ParseConfig(fdp_.ConsumeRandomLengthString(kMaxBytes));
            parser.ParseConfigFileInsecure(fdp_.ConsumeRandomLengthString(kMaxBytes));
            break;
        case 2:
            ProcessPaths(fdp_.PickValueInArray(kValidPaths));
            for (auto path : path_data_) {
                parser.ParseConfig(path);
                parser.ParseConfigFileInsecure(path);
            }
            break;
        case 3:
            ParseConfig({fdp_.ConsumeRandomLengthString(kMaxBytes)});
            break;
        default:
            ProcessPaths(fdp_.PickValueInArray(kValidPaths));
            ParseConfig(path_data_);
    }
}

void InitUeventDFuzzer::Process() {
    while (fdp_.remaining_bytes()) {
        auto invoke_ueventd_fuzzer = fdp_.PickValueInArray<const std::function<void()>>({
                [&]() {
                    std::vector<std::string> args = {""};
                    fdp_.ConsumeBool() ? args.push_back("start")
                                       : args.push_back(fdp_.ConsumeRandomLengthString(kMaxBytes));
                    CreateBootchartEnabled();
                    do_bootchart(BuiltinArguments(args, fdp_.ConsumeRandomLengthString(kMaxBytes)));

                    if (fdp_.ConsumeBool()) {
                        /*  sleep is used to explore different paths, because of mutex locks in the
                         *  source code
                         */
                        std::this_thread::sleep_for(
                                std::chrono::milliseconds(fdp_.ConsumeIntegralInRange<int32_t>(
                                        kBootchartMinWaitTime, kBootchartMaxWaitTime)));
                    }
                    args[1] = "stop";
                    do_bootchart(BuiltinArguments(args, fdp_.ConsumeRandomLengthString(kMaxBytes)));
                },
                [&]() { SwitchToMountNamespaceIfNeeded(fdp_.PickValueInArray(kNamespace)); },
                [&]() { GetCurrentMountNamespace(); },
                [&]() { SetupMountNamespaces(); },
                [&]() { InvokeParser(fdp_.ConsumeIntegralInRange<int32_t>(kMinRange, kMaxRange)); },
                [&]() { FscryptInstallKeyring(); },
                [&]() {
                    std::string ref_base_name = fdp_.ConsumeBool()
                                                        ? fdp_.PickValueInArray(kFscryptRefPath)
                                                        : fdp_.ConsumeRandomLengthString(kMaxBytes);
                    FscryptSetDirectoryPolicy(ref_base_name, fdp_.PickValueInArray(kAction),
                                              fdp_.ConsumeRandomLengthString(kMaxBytes));
                },
        });
        invoke_ueventd_fuzzer();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitUeventDFuzzer init_ueventd_fuzzer(data, size);
    init_ueventd_fuzzer.Process();
    remove(kTestScriptPath.c_str());
    return 0;
}
