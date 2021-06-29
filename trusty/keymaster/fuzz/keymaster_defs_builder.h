/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <fuzz/keymaster_fuzzer.pb.h>
#include <hardware/keymaster_defs.h>
#include <keymaster/android_keymaster.h>
#include <src/libfuzzer/libfuzzer_macro.h>
#include <stdlib.h>
#include <trusty/coverage/coverage.h>
#include <trusty/coverage/uuid.h>
#include <trusty/fuzz/counters.h>
#include <trusty/fuzz/utils.h>
#include <trusty_keymaster/ipc/keymaster_ipc.h>
#include <unistd.h>
#include <iostream>
#include <memory>

using android::trusty::coverage::CoverageRecord;
using android::trusty::fuzz::ExtraCounters;
using android::trusty::fuzz::TrustyApp;
namespace fuzz = android::trusty::keymaster::fuzz;

#define TIPC_DEV "/dev/trusty-ipc-dev0"

#define TRUSTY_APP_PORT "com.android.trusty.keymaster"
#define TRUSTY_APP_UUID "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf"
#define TRUSTY_APP_FILENAME "keymaster.syms.elf"

//#define PROTO_DEBUG(x) LOG("%s\n", x.DebugString().c_str())
#define PROTO_DEBUG(x)
#define LOG(...) printf(__VA_ARGS__)

#define ABORT(...)        \
    do {                  \
        LOG(__VA_ARGS__); \
        abort();          \
    } while (0)

enum Invariant {
    GenerateKey,
    BeginOp,
};
