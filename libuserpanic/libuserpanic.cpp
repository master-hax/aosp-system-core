/*
 *  libuserpanic.cpp
 *
 *   Copyright 2021 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <backtrace/Backtrace.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

#define CRASH_INFO _IOW('U', 179, struct userpanic_crash_info)

#define DEV_USERSPACE_PANIC "/dev/userspace_panic"
#define PROC_SYSRQ_TRIGGER  "/proc/sysrq-trigger"

struct userpanic_crash_info {
    const char* title;
    const char* msg;
};

static int request_kernel_panic(int fd, const char *title, const char *msg)
{
    struct userpanic_crash_info crash_info;
    crash_info.title = title;
    crash_info.msg = msg;
    return ioctl(fd, CRASH_INFO, &crash_info);
}

void android_panic_kernel(const char *title, const char *msg)
{
    int fd;
    std::string full_msg;

    if (msg) {
        full_msg.append(msg);
        full_msg.append("\n");
    }

    std::unique_ptr<Backtrace> backtrace(Backtrace::Create(
          BACKTRACE_CURRENT_PROCESS, BACKTRACE_CURRENT_THREAD));

    if (!backtrace->Unwind(0)) {
        full_msg.append(__FUNCTION__);
        full_msg.append(": Failed to unwind callstack.");
    } else {
        full_msg.append(__FUNCTION__);
        full_msg.append(": User callstack to panic:\n");
        for (size_t i = 0; i < backtrace->NumFrames(); i++) {
            full_msg.append(backtrace->FormatFrameData(i));
            full_msg.append("\n");
        }
    }

    fd = open(DEV_USERSPACE_PANIC, O_WRONLY);
    if (fd != -1) {
        request_kernel_panic(fd, title, full_msg.c_str());
    }
    LOG(ERROR) << __FUNCTION__ << ": failed to open /dev/userspace_panic: "
               << strerror(errno) << ", fallback to sysrq(c)";

    fd = open(PROC_SYSRQ_TRIGGER, O_WRONLY);
    if (fd != -1) {
        write(fd, "c", 1);
    }
    LOG(ERROR) << __FUNCTION__ << ": failed to open /proc/sysrq-trigger: "
               << strerror(errno);
}

#ifdef __cplusplus
}
#endif
