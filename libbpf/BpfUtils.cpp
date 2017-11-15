/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "bpf/BpfUtils.h"

namespace android {

#define ptr_to_u64(x) ((uint64_t)(uintptr_t)x)

bool hasBpfSupport() {
    struct utsname buf;
    int kernel_version_major;
    int kernel_version_minor;

    int ret = uname(&buf);
    if (ret) {
        return false;
    }
    ret = sscanf(buf.release, "%d.%d", &kernel_version_major, &kernel_version_minor);
    if (ret >= 2 &&
        ((kernel_version_major == 4 && kernel_version_minor >= 9) || (kernel_version_major > 4)))
        // Turn off the eBPF feature temporarily since the selinux rules and kernel changes are not
        // landed yet.
        // TODO: turn back on when all the other dependencies are ready.
        return true;
    return false;
}

int bpf(int cmd, bpf_attr* attr) {
    return syscall(__NR_bpf, cmd, attr, sizeof(attr));
}

int findMapEntry(int map_fd, void* key, void* value) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = ptr_to_u64(key);
    attr.value = ptr_to_u64(value);

    return bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

int getNextMapKey(int map_fd, void* key, void* next_key) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = ptr_to_u64(key);
    attr.next_key = ptr_to_u64(next_key);

    return bpf(BPF_MAP_GET_NEXT_KEY, &attr);
}

int mapRetrieve(const char* pathname, int) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64((void*)pathname);
    // TODO: Add the file flag field back after the kernel changes for bpf obj flags is merged and
    // the android uapi header is updated.
    return bpf(BPF_OBJ_GET, &attr);
}

}  // namespace android
