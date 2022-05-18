/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <lib/binder/Errors.h>
#include <lib/binder/android-base/unique_fd.h>
#include <type_traits>
#include <sys/types.h>
// #include <trusty_ipc.h>
//#include <type_traits>

namespace trusty {
namespace aidl {

using Handle = int;

struct __packed RequestHeader {
    uint32_t cmd;
    uint32_t resp_payload_size;
};

struct __packed ResponseHeader {
    uint32_t cmd;
    uint32_t resp_payload_size;
    int rc;
};

// class __packed ParcelFileDescriptor {
// public:
//     android::base::unique_fd handle;

//     // Handle methods
//     static constexpr uint32_t num_handles = 1;
//     void send_handles(Handle*& hptr) { *hptr++ = handle.release(); }
//     void recv_handles(Handle*& hptr) { handle.reset(*hptr++); }

// private:
//     // struct trusty_shm from Android has 2 32-bit fields
//     // so we reserve the space for the second one here
//     uint32_t reserved = 0;
// };
// static_assert(sizeof(ParcelFileDescriptor) == 2 * sizeof(uint32_t));

// Default implementation for all types without handles
template <typename T, typename = void>
class HandleOps {
public:
    static constexpr uint32_t num_handles = 0;
    static void send_handles(void*, Handle*& ) {}
    static void recv_handles(void*, Handle*&) {}
};

// HasHandleMembers<T> is equal to void for all types T
// that have the 3 members we need for HandleOps, and
// doesn't exist for any other types (triggering SFINAE below)
template <typename T>
using HasHandleMembers = std::void_t<
        decltype(T::num_handles),
        decltype(std::declval<T>().send_handles(std::declval<Handle*&>())),
        decltype(std::declval<T>().recv_handles(std::declval<Handle*&>()))>;

// Specialization for types that implement their own handle methods
template <typename T>
class HandleOps<T, HasHandleMembers<T>> {
public:
    static constexpr uint32_t num_handles = T::num_handles;
    static void send_handles(void* x, Handle*& hptr) {
        reinterpret_cast<T*>(x)->send_handles(hptr);
    }
    static void recv_handles(void* x, Handle*& hptr) {
        reinterpret_cast<T*>(x)->recv_handles(hptr);
    }
};

class Payload {
public:
    Payload() : mData(nullptr), mSize(0) {}
    Payload(uint8_t* data, uint32_t size) : mData(data), mSize(size) {}
    Payload(const Payload&) = delete;
    Payload& operator=(const Payload&) = delete;

    Payload(Payload&& other) : mData(other.mData), mSize(other.mSize) {
        other.reset();
    }

    Payload& operator=(Payload&& other) {
        mData = other.mData;
        mSize = other.mSize;
        other.reset();
        return *this;
    }

    const uint8_t* data() const { return mData; }

    uint8_t* data() { return mData; }

    uint32_t size() const { return mSize; }

    void resize(uint32_t size) { mSize = size; }

private:
    uint8_t* mData;
    uint32_t mSize;

    void reset() {
        mData = nullptr;
        mSize = 0;
    }
};

namespace ipc {
int connect(const char* path, uint32_t flags, android::base::unique_fd& out_fd);

int send(Handle chan,
         const void* buf,
         size_t len,
         Handle* handles,
         uint32_t num_handles);
int recv(Handle chan,
         size_t min_sz,
         void* buf,
         size_t buf_sz,
         Handle* handles,
         uint32_t num_handles);
int send(Handle chan,
         const void* hdr,
         size_t hdr_len,
         const void* payload1,
         size_t payload1_len,
         Handle* handles,
         uint32_t num_handles);
int recv(Handle chan,
         size_t min_sz,
         void* buf1,
         size_t buf1_sz,
         void* buf2,
         size_t buf2_sz,
         Handle* handles,
         uint32_t num_handles);
int send(Handle chan,
         const void* hdr,
         size_t hdr_len,
         const void* payload1,
         size_t payload1_len,
         const void* payload2,
         size_t payload2_len,
         Handle* handles,
         uint32_t num_handles);
int recv(Handle chan,
         size_t min_sz,
         void* buf1,
         size_t buf1_sz,
         void* buf2,
         size_t buf2_sz,
         void* buf3,
         size_t buf3_sz,
         Handle* handles,
         uint32_t num_handles);
}  // namespace ipc

}  // namespace aidl
}  // namespace trusty
