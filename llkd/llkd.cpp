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

#include "llkd.h"
#include "llkd_service.h"

#include <sched.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <chrono>

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android/system/core/llkd/ILlkdService.h>

using android::sp;
using android::base::ParseInt;
using android::system::core::llkd::DumpKernelStack;
using android::system::core::llkd::IsUserBuild;
using android::system::core::llkd::LlkdService;
using std::chrono::duration_cast;
using std::chrono::microseconds;

static void Usage() {
    std::cerr << "\nUsage:\n"
              << "\t./llkd          - Starts llkd deamon\n"
              << "\t./llkd -d <pid> - Dumps kernel stack of each thread for the specified pid\n\n";
}

static bool ParseArgs(int argc, char* argv[], bool* dumpStack, int* pid) {
    *dumpStack = false;
    *pid = -1;

    if (argc == 1) {
        return true;
    }
    if (argc == 3 && std::string(argv[1]) == "-d") {
        *dumpStack = true;
        return ParseInt(argv[2], pid);
    }
    return false;
}

int main(int argc, char* argv[]) {
    prctl(PR_SET_DUMPABLE, 0);

    LOG(INFO) << "started";

    bool dump_stack;
    int pid;
    sp<LlkdService> llkd_service = nullptr;

    if (!ParseArgs(argc, argv, &dump_stack, &pid)) {
        Usage();
        std::exit(EXIT_FAILURE);
    }

    if (!IsUserBuild()) {
        if (dump_stack) {
            // We only have the required permissions to dump kernel stack traces
            // on userdebug and eng builds.
            if (DumpKernelStack(pid)) {
                std::exit(EXIT_SUCCESS);
            }
            std::exit(EXIT_FAILURE);
        } else {
            // Only serve the llkd AIDL service on non-user builds.
            llkd_service = new LlkdService();
            if (!RegisterLlkdService(llkd_service)) {
                LOG(FATAL) << "Failed to register llkd_service";
            }
        }
    }

    bool enabled = llkInit();

    // Would like this policy to be automatic as part of libllkd,
    // but that would be presumptuous and bad side-effect.
    struct sched_param param;
    memset(&param, 0, sizeof(param));
    sched_setscheduler(0, SCHED_BATCH, &param);

    while (true) {
        if (enabled) {
            ::usleep(duration_cast<microseconds>(llkCheck()).count());
        } else {
            ::pause();
        }
    }
    // NOTREACHED

    LOG(INFO) << "exiting";
    return 0;
}
