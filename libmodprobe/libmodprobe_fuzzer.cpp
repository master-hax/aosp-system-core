//
// Copyright (C) 2022 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <string>
#include <vector>

#include <android-base/file.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <modprobe/modprobe.h>

#include "libmodprobe_test.h"

using namespace std::literals;

// Used by libmodprobe_ext_test to fake a kernel commandline.
std::string kernel_cmdline;

// Used by libmodprobe_ext_test to report which modules would have been loaded.
std::vector<std::string> modules_loaded;

// Used by libmodprobe_ext_test to check if requested modules are present.
std::vector<std::string> test_modules;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    TemporaryDir dir;

    test_modules.clear();
    for (int i = 0; i < 6; ++i) {
        test_modules.push_back(dir.path + fdp.ConsumeRandomLengthString(10) + ".ko"s);
    }
    for (const auto cfg_name : {"modules.alias", "modules.dep", "modules.softdep",
                                "modules.options", "modules.load", "modules.blocklist"}) {
        android::base::WriteStringToFile(fdp.ConsumeRandomLengthString(),
                                         dir.path + "/"s + cfg_name);
    }
    kernel_cmdline = fdp.ConsumeRemainingBytesAsString();

    Modprobe m({dir.path});
    m.LoadListedModules();

    return 0;
}
