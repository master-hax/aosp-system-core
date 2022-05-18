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

#include <assert.h>
// #include <lib/binder/android-base/unique_fd.h>
#include <lib/binder/Binder.h>
#include <trusty/tipc.h>


#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"

namespace trusty {
namespace aidl {
namespace ipc {

int connect(const char* path,
            uint32_t flags,
            android::base::unique_fd& out_fd) {
    (void)flags;
    int rc = tipc_connect(TRUSTY_DEVICE_NAME, path);
    if (rc < 0) {
        return rc;
    }

    out_fd.reset(rc);
    return 0;
}

int send(Handle chan,
         const void* buf,
         size_t len,
         Handle* handles,
         uint32_t num_handles) {
    (void)handles;
    if (num_handles != 0) return android::INVALID_OPERATION;
    return write(chan, buf, len);
}

int recv(Handle chan,
         size_t min_sz,
         void* buf,
         size_t buf_sz,
         Handle* handles,
         uint32_t num_handles) {
    (void)handles;
    int rc;
    if (num_handles != 0) return android::INVALID_OPERATION;
    if (buf_sz < min_sz) return android::INVALID_OPERATION;
    rc = read(chan, buf, buf_sz);
    if (rc < 0) {
        return android::IO_ERROR;
    }
    if (rc < buf_sz){
        return android::NOT_ENOUGH_DATA;
    }
    if (rc != buf_sz) return android::INVALID_OPERATION;
    return rc;
}

int send(Handle chan,
         const void* hdr,
         size_t hdr_len,
         const void* payload1,
         size_t payload1_len,
         Handle* handles,
         uint32_t num_handles) {
    (void)handles;
    if (num_handles != 0) return android::INVALID_OPERATION;
    struct iovec iovs[] = {
            {
                    .iov_base = (void*)hdr,
                    .iov_len = hdr_len,
            },
            {
                    .iov_base = (void*)payload1,
                    .iov_len = payload1_len,
            },
    };
    return tipc_send(chan, iovs, 2, NULL, 0);
}

int recv(Handle chan,
         size_t min_sz,
         void* buf1,
         size_t buf1_sz,
         void* buf2,
         size_t buf2_sz,
         Handle* handles,
         uint32_t num_handles) {
    (void)handles;
    int rc, len = 0;
    if (num_handles != 0) return android::INVALID_OPERATION;
    if (buf1_sz < min_sz) return android::INVALID_OPERATION;
    if (buf2_sz < min_sz) return android::INVALID_OPERATION;
    rc = read(chan, buf1, buf1_sz);
    if (rc < 0) {
        return android::IO_ERROR;
    }
    if (rc < buf1_sz){
        return android::NOT_ENOUGH_DATA;
    }
    len += rc;
    rc = read(chan, buf2, buf2_sz);
    if (rc < 0) {
        return android::IO_ERROR;
    }
    if (rc < buf2_sz){
        return android::NOT_ENOUGH_DATA;
    }
    len += rc;
    return len;
}

int send(Handle chan,
         const void* hdr,
         size_t hdr_len,
         const void* payload1,
         size_t payload1_len,
         const void* payload2,
         size_t payload2_len,
         Handle* handles,
         uint32_t num_handles) {
    (void)handles;
    if (num_handles != 0) return android::INVALID_OPERATION;
    struct iovec iovs[] = {
            {
                    .iov_base = (void*)hdr,
                    .iov_len = hdr_len,
            },
            {
                    .iov_base = (void*)payload1,
                    .iov_len = payload1_len,
            },
            {
                    .iov_base = (void*)payload2,
                    .iov_len = payload2_len,
            },
    };
    return tipc_send(chan, iovs, 3, NULL, 0);
}

int recv(Handle chan,
         size_t min_sz,
         void* buf1,
         size_t buf1_sz,
         void* buf2,
         size_t buf2_sz,
         void* buf3,
         size_t buf3_sz,
         Handle* handles,
         uint32_t num_handles) {
    (void)handles;
    int rc, len = 0;
    if (num_handles != 0) return android::INVALID_OPERATION;
    if (buf1_sz < min_sz) return android::INVALID_OPERATION;
    if (buf2_sz < min_sz) return android::INVALID_OPERATION;
    if (buf3_sz < min_sz) return android::INVALID_OPERATION;
    rc = read(chan, buf1, buf1_sz);
    if (rc < 0) {
        return android::IO_ERROR;
    }
    if (rc < buf1_sz){
        return android::NOT_ENOUGH_DATA;
    }
    len += rc;
    rc = read(chan, buf2, buf2_sz);
    if (rc < 0) {
        return android::IO_ERROR;
    }
    if (rc < buf2_sz){
        return android::NOT_ENOUGH_DATA;
    }
    len += rc;
    rc = read(chan, buf3, buf3_sz);
    if (rc < 0) {
        return android::IO_ERROR;
    }
    if (rc < buf3_sz){
        return android::NOT_ENOUGH_DATA;
    }
    len += rc;
    return len;

}

}  // namespace ipc
}  // namespace aidl
}  // namespace trusty
