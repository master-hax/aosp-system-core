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

#include <android-base/strings.h>
#include <block_dev_initializer.h>
#include <fuzzer/FuzzedDataProvider.h>

using namespace android::init;
constexpr int32_t kMaxBytes = 256;
constexpr int32_t kMinSize = 1;

std::string kDeviceName[] = {"fsc",
                             "modemst2",
                             "ALIGN_TO_128K_2",
                             "fsg",
                             "modemst1",
                             "cdt",
                             "cdt_backup",
                             "ALIGN_TO_128K_1",
                             "ddr",
                             "xbl_config_a",
                             "xbl_a",
                             "spunvm",
                             "tz_a",
                             "cmnlib64_b",
                             "uefisecapp_a",
                             "msadp_b",
                             "keymaster_b",
                             "vbmeta_a",
                             "secdata",
                             "qupfw_a",
                             "apdp_b",
                             "abl_b",
                             "storsec",
                             "cmnlib64_a",
                             "uefisecapp_b",
                             "tz_b",
                             "toolsfv",
                             "keymaster_a",
                             "vbmeta_b",
                             "msadp_a",
                             "splash",
                             "hyp_a",
                             "devcfg_b",
                             "imagefv_a",
                             "devinfo",
                             "aop_a",
                             "cmnlib_b",
                             "dtbo_a",
                             "uefivarstore",
                             "devcfg_a",
                             "imagefv_b",
                             "hyp_b",
                             "logfs",
                             "cmnlib_a",
                             "dtbo_b",
                             "aop_b",
                             "limits",
                             "abl_a",
                             "qupfw_b",
                             "apdp_a",
                             "xbl_config_b",
                             "xbl_b",
                             "keystore",
                             "persist",
                             "super",
                             "vbmeta_system_a",
                             "modem_b",
                             "klog",
                             "boot_b",
                             "frp",
                             "misc",
                             "userdata",
                             "ssd",
                             "vbmeta_system_b",
                             "metadata",
                             "modem_a",
                             "boot_a"};

std::vector<std::string> files;

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
    DIR* dir = opendir("/dev/block");
    struct dirent* entry;

    while ((entry = readdir(dir)) != nullptr) {
        if (android::base::StartsWith(entry->d_name, "dm-")) {
            files.push_back(entry->d_name);
        }
    }
    closedir(dir);
    return 0;
}

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
                    int32_t maxSize = sizeof(kDeviceName) / sizeof(kDeviceName[0]);
                    int32_t count = fdp.ConsumeIntegralInRange<int32_t>(kMinSize, maxSize - 1);
                    for (size_t idx = 0; idx < count; ++idx) {
                        devices.insert(kDeviceName[idx]);
                    }
                    block_dev_initializer.InitDevices(devices);
                },
                [&]() {
                    int32_t devIndex = fdp.ConsumeIntegralInRange<int32_t>(0, (files.size() - 1));
                    std::string device = files[devIndex];
                    block_dev_initializer.InitDmDevice(device);
                },
        });
        invoke_block_dev_fuzzer();
    }
    return 0;
}
