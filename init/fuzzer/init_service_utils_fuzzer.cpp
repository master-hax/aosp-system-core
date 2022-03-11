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
#include <capabilities.h>
#include <service_utils.h>
#include <fstream>
#include "fuzzer/FuzzedDataProvider.h"

using namespace android;
using namespace android::init;

constexpr int32_t kMaxStringLength = 10;
constexpr int32_t kMaxProcnetID = 20;
constexpr int32_t kMaxFileLength = 10;
constexpr int32_t kMaxNameSpacePathLength = 64;
constexpr int32_t kMaxScoketType = 6;
constexpr int32_t kMinScoketType = 1;
constexpr int32_t kMinUserGroupID = 1;
constexpr int32_t kMaxUserGroupID = 10;
const std::string kFuzzerTestFile = "/data/local/tmp/FuzzerTestDescriptorFile";
const std::string kCapMap[] = {"CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID",
                               "KILL",  "SETGID",       "SETUID",          "SETPCAP"};
enum NameSpaceFlag { NEWNS_CASE, NEWPID_CASE, NEWPID_NEWNS, kMaxValue = NEWPID_NEWNS };

class InitServiceUtilsFuzzer {
  public:
    InitServiceUtilsFuzzer(const uint8_t* data, size_t size) : fdp_(data, size){};
    void process();

  private:
    void Invokecapabilities();
    void InvokeServiceUtils();
    void CreateTestFile();
    void RemoveFile();
    FuzzedDataProvider fdp_;
    std::vector<std::string> write_pid_files_;
    std::optional<CapSet> capabilities_;
    FileDescriptor file_;
};

void InitServiceUtilsFuzzer::Invokecapabilities() {
    const std::string cap_name = fdp_.PickValueInArray(kCapMap);
    int32_t res = LookupCap(cap_name);
    if (res > 0) {
        unsigned int cap = static_cast<unsigned int>(res);
        (*capabilities_)[cap] = true;
        SetCapsForExec(*capabilities_);
    }
}

void InitServiceUtilsFuzzer::CreateTestFile() {
    std::ofstream out;
    out.open(kFuzzerTestFile, std::ios::binary);
    for (int32_t i = 0; i < kMaxFileLength; ++i) {
        out << fdp_.ConsumeRandomLengthString(kMaxStringLength) << "\n";
    }
    out.close();
}

void InitServiceUtilsFuzzer::RemoveFile() {
    remove(kFuzzerTestFile.c_str());
}

NamespaceInfo createNamespaceInfo(FuzzedDataProvider* fdp) {
    NamespaceInfo name_spaces;
    char buf[kMaxNameSpacePathLength];
    int32_t flag = fdp->ConsumeEnum<NameSpaceFlag>();
    switch (flag) {
        case NEWNS_CASE:
            name_spaces.flags |= CLONE_NEWNS;
            break;
        case NEWPID_CASE:
            name_spaces.flags |= CLONE_NEWPID;
            break;
        case NEWPID_NEWNS:
            name_spaces.flags |= CLONE_NEWPID;
            name_spaces.flags |= CLONE_NEWNS;
            break;
    }

    snprintf(buf, sizeof(buf), "/proc/%u/ns/net", fdp->ConsumeIntegralInRange(1, kMaxProcnetID));
    std::string path = buf;
    name_spaces.namespaces_to_enter.emplace_back(CLONE_NEWNET, path);

    return name_spaces;
}

SocketDescriptor createSocketDescriptorParam(FuzzedDataProvider* fdp) {
    SocketDescriptor socket_desc;
    socket_desc.name = fdp->ConsumeRandomLengthString(kMaxStringLength);
    socket_desc.type = fdp->ConsumeIntegralInRange(kMinScoketType, kMaxScoketType);
    socket_desc.uid = fdp->ConsumeIntegralInRange(kMinUserGroupID, kMaxUserGroupID);
    socket_desc.gid = fdp->ConsumeIntegralInRange(kMinUserGroupID, kMaxUserGroupID);
    socket_desc.perm = fdp->ConsumeIntegralInRange(kMinUserGroupID, kMaxUserGroupID);
    socket_desc.passcred = fdp->ConsumeBool();
    socket_desc.persist = fdp->ConsumeBool();
    return socket_desc;
}

void InitServiceUtilsFuzzer::InvokeServiceUtils() {
    while (fdp_.remaining_bytes() > 0) {
        auto service_utils = fdp_.PickValueInArray<const std::function<void()>>({
                // Invoke function to WritePidToFiles
                [&]() {
                    for (int32_t i = 0; i < kMaxFileLength; ++i) {
                        write_pid_files_.push_back(
                                fdp_.ConsumeRandomLengthString(kMaxStringLength));
                    }
                    WritePidToFiles(&write_pid_files_);
                },
                // Invoke function to Entername_spaces
                [&]() {
                    std::optional<MountNamespace> override_mount_namespace =
                            fdp_.ConsumeBool() ? NS_DEFAULT : NS_BOOTSTRAP;
                    const std::string name = fdp_.ConsumeRandomLengthString(kMaxStringLength);
                    NamespaceInfo Info = createNamespaceInfo(&fdp_);
                    EnterNamespaces(Info, name, override_mount_namespace);
                },
                // Invoke function to create socket descriptor
                [&]() {
                    SocketDescriptor socket_desc = createSocketDescriptorParam(&fdp_);
                    std::string context = fdp_.ConsumeBool()
                                                  ? fdp_.ConsumeRandomLengthString(kMaxStringLength)
                                                  : "u:object_r:snapuserd_socket:s0";
                    socket_desc.Create(fdp_.ConsumeRandomLengthString(kMaxStringLength));
                },
                // Invoke function to create file descriptor and publish that descriptor
                [&]() {
                    CreateTestFile();
                    file_.name = kFuzzerTestFile;
                    file_.type = fdp_.ConsumeBool() ? "r" : "w";
                    file_.Create();
                },
        });
        service_utils();
        RemoveFile();
    }
}

void InitServiceUtilsFuzzer::process() {
    if (fdp_.ConsumeBool()) {
        InvokeServiceUtils();
    } else {
        Invokecapabilities();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitServiceUtilsFuzzer initServiceUtilsFuzzer(data, size);
    initServiceUtilsFuzzer.process();
    return 0;
}
