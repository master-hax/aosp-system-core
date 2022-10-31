/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <chrono>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <libdm/dm_table.h>
#include <libdm/loop_control.h>

#include "test_util.h"

using namespace android;
using namespace android::base;
using namespace android::dm;
using namespace std;
using namespace std::chrono_literals;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    uint64_t val[6];

    if (size != sizeof(val)) {
        return 0;
    }

    memcpy(&val, &data[0], sizeof(*val));

    unique_fd tmp1(CreateTempFile("file_1", 4096));
    unique_fd tmp2(CreateTempFile("file_2", 4096));

    LoopDevice loop_a(tmp1, 10s);
    LoopDevice loop_b(tmp2, 10s);

    // Define a 2-sector device, with each sector mapping to the first sector
    // of one of our loop devices.
    DmTable table;
    table.Emplace<DmTargetLinear>(val[0], val[1], loop_a.device(), val[2]);
    table.Emplace<DmTargetLinear>(val[3], val[4], loop_b.device(), val[5]);

    TempDevice dev("libdm-test-dm-linear", table);
    auto& dm = DeviceMapper::Instance();
    dev_t dev_number;
    dm.GetDeviceNumber(dev.name(), &dev_number);
    std::string dev_string;
    dm.GetDeviceString(dev.name(), &dev_string);
    vector<DeviceMapper::TargetInfo> targets;
    dm.GetTableStatus(dev.name(), &targets);

    // Normally the TestDevice destructor would delete this, but at least one
    // test should ensure that device deletion works.
    dev.Destroy();
    return 0;
}
