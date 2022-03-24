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
    InitServiceFuzzer(const uint8_t* data, size_t size) : fdp_(data, size){};
    void process();

  private:
    void InvokeService();
    void InvokeFileConfig();
    void CreateTestFile();
    void RemoveFile();
    void GenerateRandoservice_Script();
    void ParseValidTestConfig(Parser* parser);
    FuzzedDataProvider fdp_;
    Service* service_ = nullptr;
    siginfo_t sig_info_ = {};
    std::vector<std::string> args_;
};

void InitServiceFuzzer::GenerateRandoservice_Script() {
    std::ofstream temp_file;
    temp_file.open(kTestScriptPath, std::ios::out | std::ios::binary);

    std::filesystem::permissions(kTestScriptPath,
                                 std::filesystem::perms::owner_all |
                                         std::filesystem::perms::group_read |
                                         std::filesystem::perms::others_read,
                                 std::filesystem::perm_options::replace);
    std::string data = "";
    temp_file << "service testFuzzer /system/bin/yes \n";
    temp_file << "class first \n";
    temp_file << "user root \n";
    temp_file << "group root system \n";

    if (fdp_.ConsumeBool()) {
        CreateTestFile();
        temp_file << "file $kFuzzerTestFile w \n";
    }

    if (fdp_.ConsumeBool()) {
        temp_file << "seclabel u:r:testFuzzer:s0 \n";
    }

    if (fdp_.ConsumeBool()) {
        temp_file << "socket testFuzzer stream 0660 system system \n";
    }

    if (fdp_.ConsumeBool()) {
        temp_file << "oom_score_adjust -600\n";
    }

    if (fdp_.ConsumeBool()) {
        temp_file << "console /dev/console\n";
        temp_file << "namespace mnt \n";
    }

    for (auto option : kServiceScripts) {
        if (fdp_.ConsumeBool()) {
            temp_file << option.c_str() << ' '
                      << fdp_.ConsumeIntegralInRange<int32_t>(kMinVal, kMaxVal) << "\n";
        }
    }
    temp_file.close();
}

void InitServiceFuzzer::InvokeFileConfig() {
    Parser parser = CreateParser(ActionManager::GetInstance(), ServiceList::GetInstance());

    auto get_service = fdp_.PickValueInArray<const std::function<void()>>({
            // Parse valid service script from valid paths
            [&]() {
                for (auto path : kValidPaths) {
                    parser.ParseConfig(path);
                }
                service_ = ServiceList::GetInstance().FindService(fdp_.PickValueInArray(kServices));
            },
            // Parse random service script from fuzzer created file
            [&]() {
                // Generate random service scripts and write in the fuzzer created script file
                GenerateRandoservice_Script();
                parser.ParseConfig(kTestScriptPath);
                service_ = ServiceList::GetInstance().FindService("testFuzzer");
            },
    });
    get_service();
}

siginfo_t getsig_infoParam(FuzzedDataProvider* fdp) {
    siginfo_t sig_info = {};
    sig_info.si_signo = fdp->PickValueInArray(kSignalNumber);
    sig_info.si_code = fdp->PickValueInArray(kSignalCode);
    sig_info.si_pid = fdp->ConsumeIntegralInRange(kMinPid, kMaxPid);
    sig_info.si_uid = fdp->ConsumeIntegralInRange(kMinPid, kMaxPid);
    sig_info.si_value.sival_int = fdp->ConsumeBool() ? 0 : kMaxSivalInt;
    return sig_info;
}

void InitServiceFuzzer::InvokeService() {
    while (fdp_.remaining_bytes() > 0) {
        auto invoke_service = fdp_.PickValueInArray<const std::function<void()>>({
                [&]() { service_->Start(); },
                [&]() { service_->StartIfNotDisabled(); },
                [&]() { service_->Stop(); },
                [&]() { service_->Terminate(); },
                [&]() { service_->Reset(); },
                [&]() { service_->Timeout(); },
                [&]() { service_->Restart(); },
                [&]() { service_->Enable(); },
                [&]() { service_->ExecStart(); },
                [&]() { service_->MarkSocketPersistent(fdp_.PickValueInArray(kSockets)); },
                [&]() {
                    Service svc("test", 0U, 0U, 0U, std::vector<gid_t>(), 0U, "", nullptr, "",
                                {"/bin/test"});
                    sig_info_ = getsig_infoParam(&fdp_);
                    svc.Reap(sig_info_);
                },
                [&]() {
                    args_.push_back("exec");
                    int32_t max = fdp_.ConsumeIntegralInRange(kMinGid, kMaxGid);
                    for (int32_t i = 0; i < max; i++) {
                        // Insert seclable, uid, gid and supplementary gid's values
                        args_.push_back(fdp_.ConsumeRandomLengthString(kMaxStringLength));
                    }
                    args_.push_back("--");
                    args_.push_back("/system/bin/toybox");
                    args_.push_back("id");
                    Service::MakeTemporaryOneshotService(args_);
                },
                [&]() {
                    if (fdp_.ConsumeBool()) {
                        auto pid = GetSnapuserdFirstStagePid();
                        service_->SetStartedInFirstStage(*pid);
                    } else {
                        pid_t pid = fdp_.ConsumeIntegralInRange(kMinPid, kMaxPid);
                        service_->SetStartedInFirstStage(pid);
                    }
                },
                [&]() { ServiceList::GetInstance().CheckAllCommands(); },
                [&]() {
                    ServiceList::GetInstance().DelayService(*service_);
                    ServiceList::GetInstance().MarkServicesUpdate();
                },
        });
        invoke_service();
    }
    RemoveFile();
}

void InitServiceFuzzer::CreateTestFile() {
    std::ofstream out;
    out.open(kFuzzerTestFile, std::ios::binary);
    for (int32_t i = 0; i < kMaxFileLength; ++i) {
        out << fdp_.ConsumeRandomLengthString(kMaxStringLength) << "\n";
    }
    out.close();
}

void InitServiceFuzzer::RemoveFile() {
    remove(kFuzzerTestFile.c_str());
    remove(kTestScriptPath.c_str());
}

void InitServiceFuzzer::process() {
    /** InvokeFileConfig() creates a Service class object which is
     * used to call APIs in InvokeService(). Hence both the
     * APIs called sequentially.
     */
    InvokeFileConfig();
    InvokeService();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitServiceFuzzer initServiceFuzzer(data, size);
    initServiceFuzzer.process();
    return 0;
}
