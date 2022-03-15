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

#include <fuzzer/FuzzedDataProvider.h>
#include <hidl/metadata.h>
#include <import_parser.h>
#include <interface_utils.h>
#include <rlimit_parser.h>

using namespace android;
using namespace android::init;

const std::vector<std::string> kValidInputs[] = {
        {"", "cpu", "10", "10"}, {"", "RLIM_CPU", "10", "10"},  {"", "12", "unlimited", "10"},
        {"", "13", "-1", "10"},  {"", "14", "10", "unlimited"}, {"", "15", "10", "-1"},
};

const std::string kValidPaths[] = {
        "/system/etc/init/hw/init.rc",
        "/system/etc/init",
};

const int32_t kMaxBytes = 256;
const std::string kValidInterfaces = "android.frameworks.vr.composer@2.0::IVrComposerClient";

class InitParserFuzzer {
  public:
    InitParserFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    void invokeParser();
    void invokeLimitParser();
    void invokeInterfaceUtils();
    InterfaceInheritanceHierarchyMap generateHierarchyMap();
    std::vector<HidlInterfaceMetadata> generateInterfaceMetadata();

    FuzzedDataProvider mFdp;
};

void InitParserFuzzer::invokeLimitParser() {
    if (mFdp.ConsumeBool()) {
        std::vector<std::string> input;
        input.push_back("");
        input.push_back(mFdp.ConsumeRandomLengthString(kMaxBytes));
        input.push_back(std::to_string(mFdp.ConsumeIntegral<int32_t>()));
        input.push_back(std::to_string(mFdp.ConsumeIntegral<int32_t>()));
        ParseRlimit(input);
    } else {
        ParseRlimit(mFdp.PickValueInArray(kValidInputs));
    }
}

std::vector<HidlInterfaceMetadata> InitParserFuzzer::generateInterfaceMetadata() {
    std::vector<HidlInterfaceMetadata> randomInterface;
    for (size_t idx = 0; idx < mFdp.ConsumeIntegral<size_t>(); ++idx) {
        HidlInterfaceMetadata metadata;
        metadata.name = mFdp.ConsumeRandomLengthString(kMaxBytes);
        for (size_t idx1 = 0; idx1 < mFdp.ConsumeIntegral<size_t>(); ++idx1) {
            metadata.inherited.push_back(mFdp.ConsumeRandomLengthString(kMaxBytes));
        }
        randomInterface.push_back(metadata);
    }
    return randomInterface;
}

InterfaceInheritanceHierarchyMap InitParserFuzzer::generateHierarchyMap() {
    InterfaceInheritanceHierarchyMap result;
    std::vector<HidlInterfaceMetadata> randomInterface;
    if (mFdp.ConsumeBool()) {
        randomInterface = generateInterfaceMetadata();
    } else {
        randomInterface = HidlInterfaceMetadata::all();
    }

    for (const HidlInterfaceMetadata& iface : randomInterface) {
        std::set<FQName> inheritedInterfaces;
        for (const std::string& intf : iface.inherited) {
            FQName fqname;
            (void)fqname.setTo(intf);
            inheritedInterfaces.insert(fqname);
        }
        FQName fqname;
        (void)fqname.setTo(iface.name);
        result[fqname] = inheritedInterfaces;
    }
    return result;
}

void InitParserFuzzer::invokeInterfaceUtils() {
    InterfaceInheritanceHierarchyMap hierarchyMap = generateHierarchyMap();
    SetKnownInterfaces(hierarchyMap);
    IsKnownInterface(mFdp.ConsumeRandomLengthString(kMaxBytes));
    std::set<std::string> interfaceSet;
    for (size_t idx = 0; idx < mFdp.ConsumeIntegral<size_t>(); ++idx) {
        if (mFdp.ConsumeBool()) {
            interfaceSet.insert(("aidl/" + mFdp.ConsumeRandomLengthString(kMaxBytes)));
        } else if (mFdp.ConsumeBool()) {
            interfaceSet.insert(mFdp.ConsumeRandomLengthString(kMaxBytes));
        } else {
            interfaceSet.insert(kValidInterfaces);
        }
    }
    CheckInterfaceInheritanceHierarchy(interfaceSet, hierarchyMap);
}

void InitParserFuzzer::invokeParser() {
    Parser parser;
    std::string name = mFdp.ConsumeBool() ? mFdp.ConsumeRandomLengthString(kMaxBytes) : "import";
    parser.AddSectionParser(name, std::make_unique<ImportParser>(&parser));
    std::string path = mFdp.ConsumeBool() ? mFdp.PickValueInArray(kValidPaths)
                                          : mFdp.ConsumeRandomLengthString(kMaxBytes);
    parser.ParseConfig(path);
    parser.ParseConfigFileInsecure(path);
}

void InitParserFuzzer::process() {
    invokeParser();
    invokeInterfaceUtils();
    invokeLimitParser();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitParserFuzzer initParserFuzzer(data, size);
    initParserFuzzer.process();
    return 0;
}
