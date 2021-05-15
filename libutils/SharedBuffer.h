/*
 * Copyright (C) 2005 The Android Open Source Project
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

/*
 * DEPRECATED.  DO NOT USE FOR NEW CODE.
 */

#pragma once

#include <atomic>
#include <stdint.h>

namespace android {

class SharedBuffer {
  public:
    // Flags to use with release().
    enum {
        eKeepStorage = 0x00000001
    };

    // Allocates a buffer of size 'size' and acquire() it.
    // Call release() to free it.
    static SharedBuffer* alloc(size_t size);

    // Frees the memory associated with the SharedBuffer.
    // Fails if there are any users associated with this SharedBuffer.
    // In other words, the buffer must have been released by all its users.
    static void dealloc(const SharedBuffer* released);

    const void* data() const { return this + 1; }

    void* data() { return this + 1; }

    size_t size() const { return mSize; }

    static inline SharedBuffer* bufferFromData(void* data) {
        return data ? static_cast<SharedBuffer*>(data) - 1 : nullptr;
    }

    static inline const SharedBuffer* bufferFromData(const void* data) {
        return data ? static_cast<const SharedBuffer*>(data) - 1 : nullptr;
    }

    static size_t sizeFromData(const void* data) { return data ? bufferFromData(data)->mSize : 0; }

    // Edit the buffer (get a writeable, or non-const, version of it).
    SharedBuffer* edit() const;

    // Edit the buffer, resizing if needed.
    SharedBuffer* editResize(size_t size) const;

    // Like edit() but fails if a copy is required.
    SharedBuffer* attemptEdit() const;

    void acquire() const;

    // Release a reference on this buffer, with the option of not
    // freeing the memory associated with it if it was the last reference.
    //
    // Returns the previous reference count.
    int32_t release(uint32_t flags = 0) const;

  private:
    SharedBuffer() = delete;
    ~SharedBuffer() = delete;
    SharedBuffer(const SharedBuffer&) = delete;
    SharedBuffer& operator=(const SharedBuffer&) = delete;

    inline bool onlyOwner() const { return (mRefs.load(std::memory_order_acquire) == 1); }

    // Must be sized to preserve correct alignment.
    mutable std::atomic<int32_t> mRefs;
    size_t mSize;
    uint32_t mReserved __attribute__((__unused__));

  public:
    // mClientMetadata is reserved for client use.  It is initialized to 0
    // and the clients can do whatever they want with it.  Note that this is
    // placed last so that it is adjcent to the buffer allocated.
    uint32_t mClientMetadata;
};

static_assert(sizeof(SharedBuffer) % 8 == 0 && (sizeof(size_t) > 4 || sizeof(SharedBuffer) == 16),
              "SharedBuffer has unexpected size");

}  // namespace android
