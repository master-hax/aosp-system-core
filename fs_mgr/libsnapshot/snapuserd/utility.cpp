// Copyright (C) 2023 The Android Open Source Project
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

#include "utility.h"

#ifdef __ANDROID__
#include <linux/memfd.h>
#endif
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <android-base/file.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;

bool SetThreadPriority([[maybe_unused]] int priority) {
#ifdef __ANDROID__
    return setpriority(PRIO_PROCESS, gettid(), priority) != -1;
#else
    return true;
#endif
}

unique_fd CreateTempFile([[maybe_unused]] const std::string& name, size_t size) {
#ifdef __ANDROID__
    unique_fd fd(memfd_create(name.c_str(), MFD_ALLOW_SEALING));
#else
    TemporaryFile f;
    unique_fd fd{f.release()};
#endif
    if (fd < 0) {
        return {};
    }
    if (size) {
        if (ftruncate(fd, size) < 0) {
            return {};
        }
#ifdef __ANDROID__
        if (fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) < 0) {
            return {};
        }
#endif
    }
    return fd;
}

}  // namespace snapshot
}  // namespace android
