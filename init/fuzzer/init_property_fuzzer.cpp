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
#include <persistent_properties.h>
#include <property_type.h>
#include <sys/stat.h>
#include <fstream>
#include "fuzzer/FuzzedDataProvider.h"

using namespace android;
using namespace android::init;
using android::init::persistent_property_filename;

const std::string kTempDir = "/data/local/tmp/";
const std::string kFuzzerPropertyFile = kTempDir + "persistent_properties";
constexpr int32_t kMaxPropertyLength = 10;
const std::string kPrefix = "persist.";
const std::string kPropertyName = kPrefix + "sys.timezone";
const std::string kPropertyValue = "America/Los_Angeles";
const std::string kLegacyPropertyFile = "/data/property/persist.properties";
const std::string kSizeSuffix[3] = {"g", "k", "m"};
constexpr int32_t kMinNumStrings = 1;
constexpr int32_t kMaxNumStrings = 10;

enum PropertyType { STRING, BOOL, INT, UINT, DOUBLE, SIZE, ENUM, RANDOM, kMaxValue = RANDOM };

class InitPropertyFuzzer {
  public:
    InitPropertyFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    void invokeCheckType();
    void invokeWritePersistentProperty();
    void removeFiles();
    void createFuzzerPropertyFile(const std::string propertyFile);
    FuzzedDataProvider mFdp;
};

void InitPropertyFuzzer::invokeCheckType() {
    std::string property_type;
    std::string value;
    int type = mFdp.ConsumeEnum<PropertyType>();
    switch (type) {
        case STRING:
            value = mFdp.ConsumeRandomLengthString(kMaxPropertyLength);
            property_type = "string";
            break;
        case BOOL:
            value = mFdp.ConsumeBool();
            property_type = "bool";
            break;
        case INT:
            value = mFdp.ConsumeIntegral<int>();
            property_type = "int";
            break;
        case UINT:
            value = mFdp.ConsumeIntegral<uint_t>();
            property_type = "uint";
            break;
        case DOUBLE:
            value = mFdp.ConsumeFloatingPoint<double>();
            property_type = "double";
            break;
        case SIZE:
            value = mFdp.ConsumeIntegral<uint_t>();
            value = value.append(mFdp.PickValueInArray(kSizeSuffix));
            property_type = "size";
            break;
        case ENUM:
            value = mFdp.ConsumeIntegral<uint_t>();
            property_type = "enum";
            break;
        case RANDOM:
            value = mFdp.ConsumeRandomLengthString(kMaxPropertyLength);
            property_type = mFdp.ConsumeRandomLengthString(kMaxPropertyLength);
            break;
    }

    CheckType(property_type, value);
}

void InitPropertyFuzzer::invokeWritePersistentProperty() {
    if (mFdp.ConsumeBool()) {
        WritePersistentProperty(kPropertyName, kPropertyValue);
    } else {
        WritePersistentProperty((kPrefix + mFdp.ConsumeRandomLengthString(kMaxPropertyLength)),
                                mFdp.ConsumeRandomLengthString(kMaxPropertyLength));
    }
}

void InitPropertyFuzzer::removeFiles() {
    remove(kFuzzerPropertyFile.c_str());
    remove(kLegacyPropertyFile.c_str());
}

void InitPropertyFuzzer::createFuzzerPropertyFile(const std::string propertyFile) {
    std::ofstream out;
    out.open(propertyFile, std::ios::binary | std::ofstream::trunc);
    chmod(propertyFile.c_str(), S_IRWXU);
    const int32_t numStrings = mFdp.ConsumeIntegralInRange(kMinNumStrings, kMaxNumStrings);
    for (int32_t i = 0; i < numStrings; ++i) {
        out << mFdp.ConsumeRandomLengthString(kMaxPropertyLength) << "\n";
    }
    out.close();
}

void InitPropertyFuzzer::process() {
    persistent_property_filename = kFuzzerPropertyFile;
    /* Property and legacy files are created using createFuzzerPropertyFile() and */
    /* are used in the below APIs. Hence createFuzzerPropertyFile() is not a part */
    /* of the lambda construct. */
    createFuzzerPropertyFile(kFuzzerPropertyFile);
    createFuzzerPropertyFile(kLegacyPropertyFile);
    auto execProperty = mFdp.PickValueInArray<const std::function<void()>>({
            [&]() { invokeCheckType(); },
            [&]() { invokeWritePersistentProperty(); },
            [&]() { LoadPersistentProperties(); },
    });
    execProperty();
    removeFiles();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitPropertyFuzzer initPropertyFuzzer(data, size);
    initPropertyFuzzer.process();
    return 0;
}
