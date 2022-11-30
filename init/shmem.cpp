/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "shmem.h"

#include <sys/mman.h>
#include <sys/stat.h>

#include <android-base/logging.h>

// Some android build bots use a sysroot that doesn't support memfd when
// compiling for the host, so we redefine it if necessary.
#if defined(__linux__) && !defined(__NR_memfd_create)
#if defined(__x86_64__)
#define __NR_memfd_create 319
#elif defined(__i386__)
#define __NR_memfd_create 356
#elif defined(__aarch64__)
#define __NR_memfd_create 279
#elif defined(__arm__)
#define __NR_memfd_create 385
#else
#error "unsupported sysroot without memfd support"
#endif
#endif

using android::base::ErrnoError;
using android::base::Error;

template <typename T>
using Result = android::base::Result<T>;

namespace android {
namespace init {

SharedMemory::SharedMemory(uint32_t size) : size_(size), memfd_(), addr_(nullptr) {}

SharedMemory::~SharedMemory() {
    Unmap();
}

Result<void> SharedMemory::CreateMemfd() {
    if (memfd_.ok()) {
        return Error() << "Already initialized";
    }
    unique_fd memfd(syscall(__NR_memfd_create, "ipc", 0));

    if (!memfd.ok()) {
        return ErrnoError() << "memfd_create()";
    }
    int ret = fallocate(memfd.get(), /*mode=*/0, /*offset=*/0, /*len=*/size_);
    if (ret < 0) {
        return ErrnoError() << "fallocate()";
    }

    memfd_ = std::move(memfd);
    return {};
}

Result<void*> SharedMemory::Map() {
    if (addr_) {
        return Error() << "Already mapped";
    }
    void* addr = mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_SHARED, memfd_.get(), 0);
    if (addr == MAP_FAILED) {
        return ErrnoError() << "mmap()";
    }
    addr_ = addr;
    return addr;
}

Result<void> SharedMemory::Unmap() {
    if (!addr_) {
        return {};
    }
    if (munmap(addr_, size_) < 0) {
        return ErrnoError() << "munmap()";
    }
    addr_ = nullptr;
    return {};
}

}  // namespace init
}  // namespace android
