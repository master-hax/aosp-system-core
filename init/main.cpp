/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "builtins.h"
#include "first_stage_init.h"
#include "init.h"
#include "selinux.h"
#include "subcontext.h"
#include "ueventd.h"

#include <android-base/logging.h>

using namespace android::init;

int main(int argc, char** argv) {
    if (!strcmp(basename(argv[0]), "ueventd")) {
        return ueventd_main(argc, argv);
    }

    if (argc < 2) {
        return FirstStageMain(argc, argv);
    }

    if (!strcmp(argv[1], "subcontext")) {
        android::base::InitLogging(argv, &android::base::KernelLogger);
        const BuiltinFunctionMap function_map;

        return SubcontextMain(argc, argv, &function_map);
    }

    if (!strcmp(argv[1], "selinux_setup")) {
        return SetupSelinux(argv);
    }

    if (!strcmp(argv[1], "second_stage")) {
        return SecondStageMain(argc, argv);
    }

    android::base::InitLogging(argv, &android::base::KernelLogger);

    LOG(ERROR) << "Unknown argument passed to init '" << argv[1] << "'";
    return 1;
}
