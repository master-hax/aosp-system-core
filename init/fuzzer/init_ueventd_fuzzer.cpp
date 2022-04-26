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
    InitUeventDFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {
        generateRandomScript();
        std::filesystem::permissions(kTestScriptPath,
                                     std::filesystem::perms::owner_all |
                                             std::filesystem::perms::group_read |
                                             std::filesystem::perms::others_read,
                                     std::filesystem::perm_options::replace);
    };
    void process();

  private:
    void createBootchartEnabled();
    void invokeParser(int32_t);
    void processPaths(std::string);
    void generateRandomScript();

    FuzzedDataProvider mFdp;
    std::string mArchType;
    std::string mTestScriptPath;
    std::vector<std::string> mPathData;
};

void InitUeventDFuzzer::createBootchartEnabled() {
    std::ofstream tempFile;
    tempFile.open(kBootchartEnabledPath, std::ios::out | std::ios::binary);
    std::string data = "";
    if (mFdp.ConsumeBool()) {
        data = mFdp.ConsumeRandomLengthString(kMaxBytes);
    }
    tempFile.write(data.c_str(), data.size());
    tempFile.close();
}

void InitUeventDFuzzer::generateRandomScript() {
    std::ofstream tempFile;
    tempFile.open(kTestScriptPath, std::ios::out | std::ios::binary);
    std::string data = "";
    for (size_t idx = 0; idx < mFdp.ConsumeIntegralInRange<size_t>(kMinLength, kMaxLength); ++idx) {
        data = mFdp.ConsumeRandomLengthString(kMaxBytes) + "\n";
    }
    tempFile.write(data.c_str(), data.size());
    tempFile.close();
}

void InitUeventDFuzzer::processPaths(std::string dirPath) {
    for (auto const& dirEntry : std::filesystem::recursive_directory_iterator(dirPath)) {
        std::string subPath = dirEntry.path();
        if (subPath.compare(subPath.size() - kCheckRC.size(), kCheckRC.size(), kCheckRC) == 0) {
            mPathData.push_back(subPath);
        }
    }
}

void InitUeventDFuzzer::invokeParser(int32_t choice) {
    TemporaryFile tf;
    Parser parser;
    std::string parserName =
            mFdp.ConsumeBool() ? "service" : mFdp.ConsumeRandomLengthString(kMaxBytes);
    parser.AddSectionParser(parserName, std::make_unique<ServiceParser>(
                                                &(ServiceList::GetInstance()), GetSubcontext(),
                                                std::nullopt /* interface_inheritance_hierarchy */,
                                                mFdp.ConsumeBool() /* fromApex */));
    switch (choice) {
        case 1:
            parser.ParseConfig(mFdp.ConsumeRandomLengthString(kMaxBytes));
            parser.ParseConfigFileInsecure(mFdp.ConsumeRandomLengthString(kMaxBytes));
            break;
        case 2:
            processPaths(mFdp.PickValueInArray(kValidPaths));
            for (auto path : mPathData) {
                parser.ParseConfig(path);
                parser.ParseConfigFileInsecure(path);
            }
            break;
        case 3:
            ParseConfig({mFdp.ConsumeRandomLengthString(kMaxBytes)});
            break;
        default:
            processPaths(mFdp.PickValueInArray(kValidPaths));
            ParseConfig(mPathData);
    }
}

void InitUeventDFuzzer::process() {
    while (mFdp.remaining_bytes()) {
        auto invokeUeventDFuzzer = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    std::vector<std::string> args = {""};
                    mFdp.ConsumeBool() ? args.push_back("start")
                                       : args.push_back(mFdp.ConsumeRandomLengthString(kMaxBytes));
                    createBootchartEnabled();
                    do_bootchart(BuiltinArguments(args, mFdp.ConsumeRandomLengthString(kMaxBytes)));

                    if (mFdp.ConsumeBool()) {
                        /*  sleep is used to explore different paths, because of mutex locks in the
                         *  source code
                         */
                        std::this_thread::sleep_for(
                                std::chrono::milliseconds(mFdp.ConsumeIntegralInRange<int32_t>(
                                        kBootchartMinWaitTime, kBootchartMaxWaitTime)));
                    }
                    args[1] = "stop";
                    do_bootchart(BuiltinArguments(args, mFdp.ConsumeRandomLengthString(kMaxBytes)));
                },
                [&]() { SwitchToMountNamespaceIfNeeded(mFdp.PickValueInArray(kNamespace)); },
                [&]() { GetCurrentMountNamespace(); },
                [&]() { SetupMountNamespaces(); },
                [&]() { invokeParser(mFdp.ConsumeIntegralInRange<int32_t>(kMinRange, kMaxRange)); },
                [&]() { FscryptInstallKeyring(); },
                [&]() {
                    std::string refBaseName = mFdp.ConsumeBool()
                                                      ? mFdp.PickValueInArray(kFscryptRefPath)
                                                      : mFdp.ConsumeRandomLengthString(kMaxBytes);
                    FscryptSetDirectoryPolicy(refBaseName, mFdp.PickValueInArray(kAction),
                                              mFdp.ConsumeRandomLengthString(kMaxBytes));
                },
        });
        invokeUeventDFuzzer();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitUeventDFuzzer initUeventDFuzzer(data, size);
    initUeventDFuzzer.process();
    remove(kTestScriptPath.c_str());
    return 0;
}
