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
#include <import_parser.h>
#include <init.h>
#include <interface_utils.h>
#include <service.h>
#include <service_list.h>
#include <snapuserd_transition.h>
#include <fstream>
#include "fuzzer/FuzzedDataProvider.h"
#include "service_parser.h"

using namespace android;
using namespace android::init;
using android::init::Service;

constexpr int32_t kMinPid = 1;
constexpr int32_t kMaxPid = 10;
constexpr int32_t kMaxStringLength = 10;
constexpr int32_t kMinGid = 4;
constexpr int32_t kMaxGid = 10;
constexpr int32_t kMaxFileLength = 10;
constexpr int32_t kMaxSivalInt = 1;
constexpr int32_t kMaxVal = 10;
constexpr int32_t kMinVal = 0;
constexpr int32_t kSignalNumber[] = {SIGABRT,   SIGBUS,  SIGFPE, SIGILL, SIGSEGV,
                                     SIGSTKFLT, SIGSTOP, SIGSYS, SIGTRAP};
constexpr int32_t kSignalCode[] = {SI_USER,    SI_KERNEL, SI_QUEUE, SI_TIMER,    SI_MESGQ,
                                   SI_ASYNCIO, SI_SIGIO,  SI_TKILL, SI_DETHREAD, SI_ASYNCNL};
const std::string kTestScriptPath = "/data/local/tmp/fuzzerServiceScriptTest.rc";
const std::string kFuzzerTestFile = "/data/local/tmp/FuzzerTestDescriptorFile";
const std::string kValidPaths[] = {
        "/system/etc/init/hw/init.rc",
        "/system/etc/init",
};
const std::string kServices[] = {"ueventd", "console", "snapuserd",   "snapuserd_proxy",
                                 "lmkd",    "logcatd", "traced_perf", "llkd-0"};
const std::string kSockets[] = {"snapuserd", "snapuserd_proxy"};
const std::string kServiceScripts[] = {"priority",
                                       "capabilities",
                                       "ioprio rt",
                                       "rlimit rtprio",
                                       "memcg.swappiness",
                                       "memcg.limit_percent",
                                       "memcg.limit_property",
                                       "memcg.limit_in_bytes",
                                       "memcg.soft_limit_in_bytes",
                                       "timeout_period",
                                       "restart_period"};

class InitServiceFuzzer {
  public:
    InitServiceFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    void invokeService();
    void invokeFileConfig();
    void createTestFile();
    void removeFile();
    void generateRandomServiceScript();
    void parseValidTestConfig(Parser* parser);
    FuzzedDataProvider mFdp;
    Service* mService = nullptr;
    FileDescriptor mFile;
    siginfo_t mSiginfo = {};
    std::vector<std::string> mArgs;
    std::vector<std::string> mWritepidFiles;
    std::optional<CapSet> mCapabilities;
};

void InitServiceFuzzer::generateRandomServiceScript() {
    std::ofstream tempFile;
    tempFile.open(kTestScriptPath, std::ios::out | std::ios::binary);

    std::filesystem::permissions(kTestScriptPath,
                                 std::filesystem::perms::owner_all |
                                         std::filesystem::perms::group_read |
                                         std::filesystem::perms::others_read,
                                 std::filesystem::perm_options::replace);
    std::string data = "";
    tempFile << "service testFuzzer /system/bin/yes \n";
    tempFile << "class first \n";
    tempFile << "user root \n";
    tempFile << "group root system \n";

    if (mFdp.ConsumeBool()) {
        createTestFile();
        tempFile << "file $kFuzzerTestFile w \n";
    }

    if (mFdp.ConsumeBool()) {
        tempFile << "seclabel u:r:testFuzzer:s0 \n";
    }

    if (mFdp.ConsumeBool()) {
        tempFile << "socket testFuzzer stream 0660 system system \n";
    }

    if (mFdp.ConsumeBool()) {
        tempFile << "oom_score_adjust -600\n";
    }

    if (mFdp.ConsumeBool()) {
        tempFile << "console /dev/console\n";
        tempFile << "namespace mnt \n";
    }

    for (auto option : kServiceScripts) {
        if (mFdp.ConsumeBool()) {
            tempFile << option.c_str() << ' '
                     << mFdp.ConsumeIntegralInRange<int32_t>(kMinVal, kMaxVal) << "\n";
        }
    }
    tempFile.close();
}

void InitServiceFuzzer::invokeFileConfig() {
    Parser parser = CreateServiceOnlyParser(ServiceList::GetInstance(), mFdp.ConsumeBool());

    auto execFunc = mFdp.PickValueInArray<const std::function<void()>>({
            // Parse valid service script from valid paths
            [&]() {
                for (auto path : kValidPaths) {
                    parser.ParseConfig(path);
                }
                mService = ServiceList::GetInstance().FindService(mFdp.PickValueInArray(kServices));
            },
            // Parse random service script from fuzzer created file
            [&]() {
                // Generate random service scripts and write in the fuzzer created script file
                generateRandomServiceScript();
                parser.ParseConfig(kTestScriptPath);
                mService = ServiceList::GetInstance().FindService("testFuzzer");
            },
    });
    execFunc();
}

siginfo_t getSiginfoParam(FuzzedDataProvider* fdp) {
    siginfo_t siginfo = {};
    siginfo.si_signo = fdp->PickValueInArray(kSignalNumber);
    siginfo.si_code = fdp->PickValueInArray(kSignalCode);
    siginfo.si_pid = fdp->ConsumeIntegralInRange(kMinPid, kMaxPid);
    siginfo.si_uid = fdp->ConsumeIntegralInRange(kMinPid, kMaxPid);
    siginfo.si_value.sival_int = fdp->ConsumeBool() ? 0 : kMaxSivalInt;
    return siginfo;
}

void InitServiceFuzzer::invokeService() {
    while (mFdp.remaining_bytes() > 0) {
        auto execService = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() { mService->Start(); },
                [&]() { mService->StartIfNotDisabled(); },
                [&]() { mService->Stop(); },
                [&]() { mService->Terminate(); },
                [&]() { mService->Reset(); },
                [&]() { mService->Timeout(); },
                [&]() { mService->Restart(); },
                [&]() { mService->Enable(); },
                [&]() { mService->ExecStart(); },
                [&]() { mService->MarkSocketPersistent(mFdp.PickValueInArray(kSockets)); },
                [&]() {
                    Service svc("test", 0U, 0U, 0U, std::vector<gid_t>(), 0U, "", nullptr,
                                {"/bin/test"});
                    mSiginfo = getSiginfoParam(&mFdp);
                    svc.Reap(mSiginfo);
                },
                [&]() {
                    mArgs.push_back("exec");
                    int32_t max = mFdp.ConsumeIntegralInRange(kMinGid, kMaxGid);
                    for (int32_t i = 0; i < max; i++) {
                        // Insert seclable, uid, gid and supplementary gid's values
                        mArgs.push_back(mFdp.ConsumeRandomLengthString(kMaxStringLength));
                    }
                    mArgs.push_back("--");
                    mArgs.push_back("/system/bin/toybox");
                    mArgs.push_back("id");
                    Service::MakeTemporaryOneshotService(mArgs);
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        auto pid = GetSnapuserdFirstStagePid();
                        mService->SetStartedInFirstStage(*pid);
                    } else {
                        pid_t pid = mFdp.ConsumeIntegralInRange(kMinPid, kMaxPid);
                        mService->SetStartedInFirstStage(pid);
                    }
                },
                [&]() { ServiceList::GetInstance().CheckAllCommands(); },
                [&]() {
                    ServiceList::GetInstance().DelayService(*mService);
                    ServiceList::GetInstance().MarkServicesUpdate();
                },
        });
        execService();
    }
    removeFile();
}

void InitServiceFuzzer::createTestFile() {
    std::ofstream out;
    out.open(kFuzzerTestFile, std::ios::binary);
    for (int32_t i = 0; i < kMaxFileLength; ++i) {
        out << mFdp.ConsumeRandomLengthString(kMaxStringLength) << "\n";
    }
    out.close();
}

void InitServiceFuzzer::removeFile() {
    remove(kFuzzerTestFile.c_str());
    remove(kTestScriptPath.c_str());
}

void InitServiceFuzzer::process() {
    /** invokeFileConfig() creates a Service class object which is
     * used to call APIs in invokeService(). Hence both the
     * APIs called sequentially.
     */
    invokeFileConfig();
    invokeService();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitServiceFuzzer initServiceFuzzer(data, size);
    initServiceFuzzer.process();
    return 0;
}
