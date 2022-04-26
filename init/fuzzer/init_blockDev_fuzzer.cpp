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

#include <block_dev_initializer.h>
#include <fuzzer/FuzzedDataProvider.h>

using namespace android::init;
constexpr int32_t kMaxBytes = 256;
constexpr int32_t kMinSize = 1;
constexpr int32_t kMaxSize = 1000;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    BlockDevInitializer block_dev_initializer;
    std::set<std::string> devices;
    while (fdp.remaining_bytes()) {
        auto invoke_block_dev_fuzzer = fdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    block_dev_initializer.InitDmUser(fdp.ConsumeRandomLengthString(kMaxBytes));
                },
                [&]() {
                    for (size_t idx = 0;
                         idx < fdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize); ++idx) {
                        devices.insert(fdp.ConsumeRandomLengthString(kMaxBytes));
                    }
                    block_dev_initializer.InitDevices(devices);
                },
                [&]() {
                    block_dev_initializer.InitDmDevice(fdp.ConsumeRandomLengthString(kMaxBytes));
                },
        });
        invoke_block_dev_fuzzer();
    }
    return 0;
}
