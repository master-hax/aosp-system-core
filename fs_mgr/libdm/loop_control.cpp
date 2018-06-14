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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>

#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

#include "loop_control.h"

LoopControl::~LoopControl() {
    if (control_fd_ < 0) {
        return;
    }

    ::close(control_fd_);
}

bool LoopControl::attach(const std::string& path, std::string* loopdev) const {
    if (!FindFreeLoopDevice(loopdev)) {
        LOG(ERROR) << "Failed to attach [" << path << "] to [" << *loopdev << "]";
        return false;
    }

    android::base::unique_fd file_fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_RDWR | O_CLOEXEC)));
    if (file_fd < 0) {
        PLOG(ERROR) << "Failed to open: " << path;
        return false;
    }

    android::base::unique_fd loop_fd(TEMP_FAILURE_RETRY(open(loopdev->c_str(), O_RDWR | O_CLOEXEC)));
    if (loop_fd < 0) {
        PLOG(ERROR) << "Failed to open: " << *loopdev;
        return false;
    }

    int rc = ioctl(loop_fd, LOOP_SET_FD, file_fd.get());
    if (rc < 0) {
        PLOG(ERROR) << "Failed LOOP_SET_FD for '" << path << "'";
        return false;
    }

    return true;
}

bool LoopControl::detach(const std::string& loopdev) const {
    if (loopdev.empty()) {
        LOG(ERROR) << "Must provide a loopback device";
        return false;
    }

    android::base::unique_fd loop_fd(TEMP_FAILURE_RETRY(open(loopdev.c_str(), O_RDWR | O_CLOEXEC)));
    if (loop_fd < 0) {
        PLOG(ERROR) << "Failed to open: " << loopdev;
        return false;
    }

    int rc = ioctl(loop_fd, LOOP_CLR_FD, 0);
    if (rc) {
        PLOG(ERROR) << "Failed LOOP_CLR_FD for '" << loopdev << "'";
        return false;
    }

    return true;
}

// private methods
bool LoopControl::FindFreeLoopDevice(std::string* loopdev) const {
    loopdev->clear();

    int rc = ioctl(control_fd_, LOOP_CTL_GET_FREE);
    if (rc < 0) {
        PLOG(ERROR) << "Failed to get free loop back device";
        return false;
    }

    // Ueventd on android creates all loopback devices as /dev/block/loopX
    // The total number of available devices is determined by 'loop.max_part'
    // kernel command line argument.
    loopdev->assign(::android::base::StringPrintf("/dev/block/loop%d", rc));
    return true;
}
