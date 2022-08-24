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

#include "cutils/native_handle_fdsan.h"

#include <android/fdsan.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

namespace {

uint64_t get_fdsan_tag(const native_handle_t* handle) {
    return android_fdsan_create_owner_tag(ANDROID_FDSAN_OWNER_TYPE_NATIVE_HANDLE,
                                          reinterpret_cast<uint64_t>(handle));
}

void swap_fdsan_tags(const native_handle_t* handle, uint64_t expected_tag, uint64_t new_tag) {
    if (!handle || handle->version != sizeof(native_handle_t)) return;

    for (int i = 0; i < handle->numFds; i++) {
        android_fdsan_exchange_owner_tag(handle->data[i], expected_tag, new_tag);
    }
}

}  // anonymous namespace

void native_handle_set_fdsan_tag(const native_handle_t* handle) {
    swap_fdsan_tags(handle, /*expected_tag=*/0, get_fdsan_tag(handle));
}

void native_handle_unset_fdsan_tag(const native_handle_t* handle) {
    swap_fdsan_tags(handle, get_fdsan_tag(handle), /*new_tag=*/0);
}

int native_handle_close_with_tag(const native_handle_t* handle) {
    // Keep implementation in sync with native_handle_close()
    if (!handle) return 0;

    if (handle->version != sizeof(native_handle_t)) return -EINVAL;

    uint64_t tag = get_fdsan_tag(handle);
    int saved_errno = errno;
    const int numFds = handle->numFds;
    for (int i = 0; i < numFds; ++i) {
        android_fdsan_close_with_tag(handle->data[i], tag);
    }
    errno = saved_errno;
    return 0;
}