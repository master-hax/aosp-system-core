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

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <unistd.h>

#include "builtins.h"
#include "first_stage_init.h"
#include "init.h"
#include "selinux.h"
#include "subcontext.h"
#include "ueventd.h"

#include <android-base/logging.h>
#include <async_safe/log.h>

#if __has_feature(address_sanitizer)
#include <sanitizer/asan_interface.h>
#elif __has_feature(hwaddress_sanitizer)
#include <sanitizer/hwasan_interface.h>
#endif

#if __has_feature(address_sanitizer) || __has_feature(hwaddress_sanitizer)
// Load asan.options if it exists since these are not yet in the environment.
// Always ensure detect_container_overflow=0 as there are false positives with this check.
// Always ensure abort_on_error=1 to ensure we reboot to bootloader for development builds.
extern "C" const char* __asan_default_options() {
    return "include_if_exists=/system/asan.options:detect_container_overflow=0:abort_on_error=1";
}

__attribute__((no_sanitize("address", "memory", "thread", "undefined"))) extern "C" void
__sanitizer_report_error_summary(const char* summary) {
    LOG(ERROR) << "Init (error summary): " << summary;
}

__attribute__((no_sanitize("address", "memory", "thread", "undefined"))) static void
AsanReportCallback(const char* str) {
    LOG(ERROR) << "Init: " << str;
}
#endif

using namespace android::init;

#if defined(__aarch64__)

static void MyLogMessage(const char* msg) {
    LOG(INFO) << "log_info: " << msg;
    async_safe_format_log(ANDROID_LOG_FATAL, "init", "async_log: %s", msg);
    android::base::KernelLogger(android::base::MAIN, android::base::WARNING, "init_kernel", nullptr,
                                0, msg);
}

static void SigILLHandler(int, siginfo_t* si, void* data) {
    char msg[512];
    snprintf(msg, sizeof(msg), "SigILLHandler, signo %d, code %d\n", si->si_signo, si->si_code);
    MyLogMessage(msg);
    ucontext_t* uc = (ucontext_t*)data;
    int instruction_length = 4;
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd != -1) {
        while (true) {
            ssize_t n = read(fd, msg, sizeof(msg) - 1);
            if (n <= 0) {
                break;
            }
            msg[n] = '\0';
            MyLogMessage(msg);
        }
        close(fd);
    }
    uc->uc_mcontext.pc += instruction_length;
}
#endif

int main(int argc, char** argv) {
#if __has_feature(address_sanitizer)
    __asan_set_error_report_callback(AsanReportCallback);
#elif __has_feature(hwaddress_sanitizer)
    __hwasan_set_error_report_callback(AsanReportCallback);
#endif
#if defined(__aarch64__)
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    sigfillset(&action.sa_mask);
    action.sa_sigaction = SigILLHandler;
    action.sa_flags = SA_RESTART | SA_SIGINFO;
    sigaction(SIGILL, &action, nullptr);
#endif
    // Boost prio which will be restored later
    setpriority(PRIO_PROCESS, 0, -20);
    if (!strcmp(basename(argv[0]), "ueventd")) {
        return ueventd_main(argc, argv);
    }

    if (argc > 1) {
        if (!strcmp(argv[1], "subcontext")) {
            android::base::InitLogging(argv, &android::base::KernelLogger);
            LOG(INFO) << "Init stage " << argv[1];
            const BuiltinFunctionMap& function_map = GetBuiltinFunctionMap();

            return SubcontextMain(argc, argv, &function_map);
        }

        if (!strcmp(argv[1], "selinux_setup")) {
            return SetupSelinux(argv);
        }

        if (!strcmp(argv[1], "second_stage")) {
            return SecondStageMain(argc, argv);
        }
    }

    return FirstStageMain(argc, argv);
}
