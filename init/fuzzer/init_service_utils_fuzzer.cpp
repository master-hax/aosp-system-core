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
    InitServiceUtilsFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    void invokecapabilities();
    void invokeServiceUtils();
    void createTestFile();
    void removeFile();
    FuzzedDataProvider mFdp;
    std::vector<std::string> mWritepidFiles;
    std::optional<CapSet> mCapabilities;
    FileDescriptor mFile;
};

void InitServiceUtilsFuzzer::invokecapabilities() {
    const std::string cap_name = mFdp.PickValueInArray(kCapMap);
    int32_t res = LookupCap(cap_name);
    if (res > 0) {
        unsigned int cap = static_cast<unsigned int>(res);
        (*mCapabilities)[cap] = true;
        SetCapsForExec(*mCapabilities);
    }
}

void InitServiceUtilsFuzzer::createTestFile() {
    std::ofstream out;
    out.open(kFuzzerTestFile, std::ios::binary);
    for (int32_t i = 0; i < kMaxFileLength; ++i) {
        out << mFdp.ConsumeRandomLengthString(kMaxStringLength) << "\n";
    }
    out.close();
}

void InitServiceUtilsFuzzer::removeFile() {
    remove(kFuzzerTestFile.c_str());
}

NamespaceInfo createNamespaceInfo(FuzzedDataProvider* fdp) {
    NamespaceInfo namespaces;
    char buf[kMaxNameSpacePathLength];
    int32_t namespace_flag = fdp->ConsumeEnum<NameSpaceFlag>();
    switch (namespace_flag) {
        case NEWNS_CASE:
            namespaces.flags |= CLONE_NEWNS;
            break;
        case NEWPID_CASE:
            namespaces.flags |= CLONE_NEWPID;
            break;
        case NEWPID_NEWNS:
            namespaces.flags |= CLONE_NEWPID;
            namespaces.flags |= CLONE_NEWNS;
            break;
    }

    snprintf(buf, sizeof(buf), "/proc/%u/ns/net", fdp->ConsumeIntegralInRange(1, kMaxProcnetID));
    std::string path = buf;
    namespaces.namespaces_to_enter.emplace_back(CLONE_NEWNET, path);

    return namespaces;
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

void InitServiceUtilsFuzzer::invokeServiceUtils() {
    while (mFdp.remaining_bytes() > 0) {
        auto execFunc = mFdp.PickValueInArray<const std::function<void()>>({
                // Invoke function to WritePidToFiles
                [&]() {
                    for (int32_t i = 0; i < kMaxFileLength; ++i) {
                        mWritepidFiles.push_back(mFdp.ConsumeRandomLengthString(kMaxStringLength));
                    }
                    WritePidToFiles(&mWritepidFiles);
                },
                // Invoke function to EnterNamespaces
                [&]() {
                    std::optional<MountNamespace> override_mount_namespace =
                            mFdp.ConsumeBool() ? NS_DEFAULT : NS_BOOTSTRAP;
                    const std::string name = mFdp.ConsumeRandomLengthString(kMaxStringLength);
                    NamespaceInfo Info = createNamespaceInfo(&mFdp);
                    EnterNamespaces(Info, name, override_mount_namespace);
                },
                // Invoke function to create socket descriptor
                [&]() {
                    SocketDescriptor socketDesc = createSocketDescriptorParam(&mFdp);
                    std::string context = mFdp.ConsumeBool()
                                                  ? mFdp.ConsumeRandomLengthString(kMaxStringLength)
                                                  : "u:object_r:snapuserd_socket:s0";
                    socketDesc.Create(mFdp.ConsumeRandomLengthString(kMaxStringLength));
                },
                // Invoke function to create file descriptor and publish that descriptor
                [&]() {
                    createTestFile();
                    mFile.name = kFuzzerTestFile;
                    mFile.type = mFdp.ConsumeBool() ? "r" : "w";
                    mFile.Create();
                },
        });
        execFunc();
        removeFile();
    }
}

void InitServiceUtilsFuzzer::process() {
    if (mFdp.ConsumeBool()) {
        invokeServiceUtils();
    } else {
        invokecapabilities();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitServiceUtilsFuzzer initServiceUtilsFuzzer(data, size);
    initServiceUtilsFuzzer.process();
    return 0;
}
