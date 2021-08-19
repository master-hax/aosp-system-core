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

#define LOG_TAG "libuserpanic"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <android/userpanic.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#define DEV_USERSPACE_PANIC "/dev/userspace_panic"
#define PROC_SYSRQ_TRIGGER  "/proc/sysrq-trigger"

using android::base::unique_fd;

void android_panic_kernel(const char* title)
{
    const char cmd = 'c';
    const char version = 0;
    uint32_t data_size = strlen(title);

    unique_fd panic_fd(open(DEV_USERSPACE_PANIC, O_WRONLY | O_CLOEXEC));
    if (panic_fd.get() != -1) {
        std::string data;
        data.append(&cmd, sizeof(cmd));
        data.append(&version, sizeof(version));
        data.append((const char*)&data_size, sizeof(data_size));
        data.append(title);
        if (TEMP_FAILURE_RETRY(
                write(panic_fd.get(), data.c_str(), data.size())) != 1) {
            PLOG(ERROR) << "Failed to write " DEV_USERSPACE_PANIC;
        }
    } else {
        PLOG(ERROR) << "Failed to open " DEV_USERSPACE_PANIC;
    }

    unique_fd sysrq_fd(open(PROC_SYSRQ_TRIGGER, O_WRONLY | O_CLOEXEC));
    if (sysrq_fd.get() != -1) {
        if (TEMP_FAILURE_RETRY(write(sysrq_fd.get(), "c", 1)) != 1) {
            PLOG(ERROR) << "Failed to write " PROC_SYSRQ_TRIGGER;
        }
    } else {
        PLOG(ERROR) << "Failed to open " PROC_SYSRQ_TRIGGER;
    }

    /* No return */
    while (true) pause();
}
