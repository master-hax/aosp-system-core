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

#include "llkd_service.h"

#include <sstream>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <procinfo/process.h>

namespace android {
namespace system {
namespace core {
namespace llkd {

static constexpr char kLlkdService[] = "llkd_service";

bool IsUserBuild() {
    return base::GetProperty("ro.build.type", "") == "user";
}

bool RegisterLlkdService(sp<LlkdService> service) {
    auto status = defaultServiceManager()->addService(String16(kLlkdService), service);
    if (status != OK) {
        return false;
    }
    status_t err = ProcessState::self()->setThreadPoolMaxThreadCount(1);
    if (err != OK) {
        LOG(WARNING) << "Failed to set max threads in pool: " << err;
    }
    ProcessState::self()->startThreadPool();
    return true;
}

bool DumpKernelStack(int pid) {
    sp<IBinder> service = defaultServiceManager()->getService(String16(kLlkdService));
    if (service == nullptr) {
        std::cout << "Failed to get " << kLlkdService << '\n';
        return false;
    }
    std::string stack;
    auto status = interface_cast<ILlkdService>(service)->DumpKernelStack(pid, &stack);
    if (!status.isOk()) {
        std::cout << "Failed to dump kernel stack for pid " << pid << '\n';
        std::cout << status << '\n';
        return false;
    }
    std::cout << stack;
    return true;
}

binder::Status LlkdService::DumpKernelStack(int pid, std::string* stack) {
    if (pid <= 0) {
        return binder::Status::fromExceptionCode(binder::Status::Exception::EX_ILLEGAL_ARGUMENT,
                                                 String8("TID must be a positive integer"));
    };

    if (IsUserBuild()) {
        return binder::Status::fromExceptionCode(
                binder::Status::Exception::EX_SECURITY,
                String8("Kernel stack traces can only be read on eng and userdebug builds"));
    }

    stack->clear();

    std::vector<pid_t> tids;
    if (!procinfo::GetProcessTids(pid, &tids)) {
        return binder::Status::fromExceptionCode(binder::Status::Exception::EX_ILLEGAL_STATE,
                                                 String8("Failed to get process TIDs"));
    }

    std::stringstream data;
    for (int tid : tids) {
        std::string path =
                "/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid) + "/stack";
        std::string stack_str;
        if (!base::ReadFileToString(path, &stack_str, true)) {
            PLOG(WARNING) << "llkd_service: Failed to read \"" << path << "\"";
            continue;
        }
        data << "sysTid=" << tid << "\n" << stack_str << "\n";
    }

    *stack = "\n" + data.str();

    return binder::Status::ok();
}

}  // namespace llkd
}  // namespace core
}  // namespace system
}  // namespace android
