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

#include <utils/String16.h>
#include <utils/Log.h>

#include "SharedBuffer.h"

namespace android {

static inline char16_t* getEmptyString() {
    static const StaticString16 emptyString(u"");
    return const_cast<char16_t*>(emptyString.string());
}

// ---------------------------------------------------------------------------

void* String16::alloc(size_t size) {
    SharedBuffer* buf = SharedBuffer::alloc(size);
    buf->mClientMetadata = kIsSharedBufferAllocated;
    return buf;
}

char16_t* String16::allocFromUTF8(const char* u8str, size_t u8len) {
    if (u8len == 0) return getEmptyString();

    ssize_t u16len = utf8_to_utf16_length((const uint8_t*)u8str, u8len);
    if (u16len < 0) return getEmptyString();

    // Our internal representation includes a null character.
    size_t size = size_t(u16len) + 1U;
    if (__builtin_mul_overflow(size, sizeof(char16_t), &size)) return getEmptyString();

    SharedBuffer* buf = static_cast<SharedBuffer*>(alloc(size));
    if (!buf) return getEmptyString();

    char16_t* u16str = static_cast<char16_t*>(buf->data());
    utf8_to_utf16(reinterpret_cast<const uint8_t*>(u8str), u8len, u16str, size_t(u16len) + 1);
    return u16str;
}

char16_t* String16::allocFromUTF16(const char16_t* u16str, size_t u16len) {
    if (u16len == 0) return getEmptyString();

    // Our internal representation includes a null character.
    size_t size = u16len;
    if (__builtin_add_overflow(size, 1, &size) ||
        __builtin_mul_overflow(size, sizeof(char16_t), &size))
        return getEmptyString();

    SharedBuffer* buf = static_cast<SharedBuffer*>(alloc(size));
    if (!buf) return getEmptyString();

    char16_t* str = static_cast<char16_t*>(buf->data());
    memcpy(str, u16str, u16len * sizeof(char16_t));
    str[u16len] = 0;
    return str;
}

// ---------------------------------------------------------------------------

String16::String16() : mString(getEmptyString()) {}

String16::String16(const String16& o) : mString(o.mString) {
    acquire();
}

String16::String16(String16&& o) noexcept : mString(o.mString) {
    o.mString = getEmptyString();
}

String16::String16(const String16& o, size_t len, size_t begin) : mString(getEmptyString()) {
    setTo(o, len, begin);
}

String16::String16(const char16_t* o) : mString(allocFromUTF16(o, strlen16(o))) {}

String16::String16(const char16_t* o, size_t len) : mString(allocFromUTF16(o, len)) {}

String16::String16(const String8& o) : mString(allocFromUTF8(o.string(), o.size())) {}

String16::String16(const char* o) : mString(allocFromUTF8(o, strlen(o))) {}

String16::String16(const char* o, size_t len) : mString(allocFromUTF8(o, len)) {}

String16::~String16() {
    release();
}

String16& String16::operator=(String16&& other) noexcept {
    release();
    mString = other.mString;
    other.mString = getEmptyString();
    return *this;
}

size_t String16::size() const {
    if (isStaticString()) return staticStringSize();
    return SharedBuffer::sizeFromData(mString) / sizeof(char16_t) - 1;
}

void String16::setTo(const String16& other) {
    release();
    mString = other.mString;
    acquire();
}

status_t String16::setTo(const String16& other, size_t len, size_t begin) {
    if (&other == this) LOG_ALWAYS_FATAL("Self-assignment not implemented");

    const size_t N = other.size();
    if (begin >= N) {
        release();
        mString = getEmptyString();
        return OK;
    }

    if (len > N - begin) len = N - begin;

    if (begin == 0 && len == N) {
        setTo(other);
        return OK;
    }

    return setTo(other.string() + begin, len);
}

status_t String16::setTo(const char16_t* other) {
    return setTo(other, strlen16(other));
}

status_t String16::setTo(const char16_t* other, size_t len) {
    size_t size = len;
    if (__builtin_add_overflow(size, 1, &size) ||
        __builtin_mul_overflow(size, sizeof(char16_t), &size)) {
        release();
        mString = getEmptyString();
        return NO_MEMORY;
    }

    SharedBuffer* buf = static_cast<SharedBuffer*>(editResize(size));
    if (!buf) return NO_MEMORY;

    char16_t* str = static_cast<char16_t*>(buf->data());
    memmove(str, other, len * sizeof(char16_t));
    str[len] = 0;
    mString = str;
    return OK;
}

status_t String16::append(const String16& other) {
    return append(other.string(), other.size());
}

status_t String16::append(const char16_t* chrs, size_t otherLen) {
    const size_t myLen = size();
    if (myLen == 0) return setTo(chrs, otherLen);

    if (otherLen == 0) return OK;

    size_t size = myLen;
    if (__builtin_add_overflow(size, otherLen, &size) ||
        __builtin_add_overflow(size, 1, &size) ||
        __builtin_mul_overflow(size, sizeof(char16_t), &size)) return NO_MEMORY;

    SharedBuffer* buf = static_cast<SharedBuffer*>(editResize(size));
    if (!buf) return NO_MEMORY;

    char16_t* str = static_cast<char16_t*>(buf->data());
    memcpy(str + myLen, chrs, otherLen * sizeof(char16_t));
    str[myLen + otherLen] = 0;
    mString = str;
    return OK;
}

status_t String16::insert(size_t pos, const char16_t* chrs) {
    return insert(pos, chrs, strlen16(chrs));
}

status_t String16::insert(size_t pos, const char16_t* chrs, size_t len) {
    const size_t myLen = size();
    if (myLen == 0) return setTo(chrs, len);

    if (len == 0) return OK;

    if (pos > myLen) pos = myLen;

    size_t size = myLen;
    if (__builtin_add_overflow(size, len, &size) || __builtin_add_overflow(size, 1, &size) ||
        __builtin_mul_overflow(size, sizeof(char16_t), &size))
        return NO_MEMORY;

    SharedBuffer* buf = static_cast<SharedBuffer*>(editResize(size));
    if (!buf) return NO_MEMORY;

    char16_t* str = static_cast<char16_t*>(buf->data());
    if (pos < myLen) memmove(str + pos + len, str + pos, (myLen - pos) * sizeof(char16_t));
    memcpy(str + pos, chrs, len * sizeof(char16_t));
    str[myLen + len] = 0;
    mString = str;
    return OK;
}

ssize_t String16::findFirst(char16_t c) const {
    const size_t N = size();
    for (ssize_t i = 0; i < N; ++i) {
        if (mString[i] == c) return i;
    }
    return -1;
}

ssize_t String16::findLast(char16_t c) const {
    for (ssize_t i = size() - 1; i >= 0; i--) {
        if (mString[i] == c) return i;
    }
    return -1;
}

bool String16::startsWith(const String16& prefix) const {
    const size_t ps = prefix.size();
    if (ps > size()) return false;
    return strzcmp16(mString, ps, prefix.string(), ps) == 0;
}

bool String16::startsWith(const char16_t* prefix) const {
    const size_t ps = strlen16(prefix);
    if (ps > size()) return false;
    return strncmp16(mString, prefix, ps) == 0;
}

bool String16::contains(const char16_t* chrs) const {
    return strstr16(mString, chrs) != nullptr;
}

void* String16::editResize(size_t newSize) {
    SharedBuffer* buf;
    if (isStaticString()) {
        size_t copySize = size();
        if (__builtin_add_overflow(copySize, 1, &copySize) ||
            __builtin_mul_overflow(copySize, sizeof(char16_t), &copySize))
            return nullptr;

        if (newSize < copySize) copySize = newSize;

        buf = static_cast<SharedBuffer*>(alloc(newSize));
        if (buf) memcpy(buf->data(), mString, copySize);
    } else {
        buf = SharedBuffer::bufferFromData(mString)->editResize(newSize);
        buf->mClientMetadata = kIsSharedBufferAllocated;
    }
    return buf;
}

void String16::acquire() {
    if (!isStaticString()) SharedBuffer::bufferFromData(mString)->acquire();
}

void String16::release() {
    if (!isStaticString()) SharedBuffer::bufferFromData(mString)->release();
}

bool String16::isStaticString() const {
    // See String16.h for notes on the memory layout of String16::StaticData and
    // SharedBuffer.
    static_assert(sizeof(SharedBuffer) - offsetof(SharedBuffer, mClientMetadata) == 4);
    const uint32_t* p = reinterpret_cast<const uint32_t*>(mString);
    return (*(p - 1) & kIsSharedBufferAllocated) == 0;
}

size_t String16::staticStringSize() const {
    // See String16.h for notes on the memory layout of String16::StaticData and
    // SharedBuffer.
    static_assert(sizeof(SharedBuffer) - offsetof(SharedBuffer, mClientMetadata) == 4);
    const uint32_t* p = reinterpret_cast<const uint32_t*>(mString);
    return static_cast<size_t>(*(p - 1));
}

status_t String16::replaceAll(char16_t replaceThis, char16_t withThis) {
    const size_t N = size();
    bool edited = false;
    for (size_t i = 0; i < N; ++i) {
        if (mString[i] == replaceThis) {
            if (!edited) {
                SharedBuffer* buf;
                size_t newSize = size();
                if (__builtin_add_overflow(newSize, 1, &newSize) ||
                    __builtin_mul_overflow(newSize, sizeof(char16_t), &newSize) ||
                    !(buf = static_cast<SharedBuffer*>(editResize(newSize))))
                    return NO_MEMORY;
                mString = static_cast<char16_t*>(buf->data());
                edited = true;
            }
            const_cast<char16_t*>(mString)[i] = withThis;
        }
    }
    return OK;
}

}  // namespace android
