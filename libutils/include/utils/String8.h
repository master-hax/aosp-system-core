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

#if 1

#pragma once

// TODO: remove these
#include <iostream>
#include <stdarg.h>
#include <utils/Compat.h>
#include <utils/String16.h>
#include <utils/Unicode.h>
#include <bitset>
#include <cstring>

#include <string>

#include <codecvt>
#include <locale>

namespace android {

#define String8(...) ::android::toString8(__VA_ARGS__)
typedef std::string String8;

typedef int32_t status_t;

inline status_t appendFormatV(std::string& s, const char* fmt, va_list args) {
    int n;
    va_list tmp_args;

    /* args is undefined after vsnprintf.
     * So we need a copy here to avoid the
     * second vsnprintf access undefined args.
     */
    va_copy(tmp_args, args);
    n = vsnprintf(nullptr, 0, fmt, tmp_args);
    va_end(tmp_args);

    if (n < 0) return INT32_MIN;  // UNKNOWN_ERROR;

    char buf[n + 1];
    vsnprintf(buf, n + 1, fmt, args);
    s += buf;

    return 0;
}

inline status_t appendFormat(std::string& s, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    const auto result = appendFormatV(s, fmt, args);

    va_end(args);

    return result;
}

inline String8 String8formatV(const char* fmt, va_list args) {
    std::string result;
    appendFormatV(result, fmt, args);
    return result;
}

inline std::string String8format(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    std::string result(String8formatV(fmt, args));

    va_end(args);
    return result;
}

inline char* lockBuffer(std::string& s, size_t len) {
    char* buf = new char[len + 1];
    memcpy(buf, s.c_str(), std::min(s.size() + 1, len));
    buf[len] = '\0';
    return buf;
}

inline void unlockBuffer(std::string& s, char* buf, size_t len) {
    s = std::string(buf, len);
    delete[] buf;
}

inline void priv_setPathName(String8& s, const char* name) {
    size_t len = strlen(name);
    char* buf = lockBuffer(s, len);

    memcpy(buf, name, len);

    // remove trailing path separator, if present
    if (len > 0 && buf[len - 1] == OS_PATH_SEPARATOR) len--;
    buf[len] = '\0';

    unlockBuffer(s, buf, len);
}

inline std::string& appendPath(std::string& s, const char* name) {
    // TODO: The test below will fail for Win32 paths. Fix later or ignore.
    if (name[0] != OS_PATH_SEPARATOR) {
        if (*name == '\0') {
            // nothing to do
            return s;
        }

        size_t len = s.length();
        if (len == 0) {
            // no existing filename, just use the new one
            priv_setPathName(s, name);
            return s;
        }

        // make room for oldPath + '/' + newPath
        int newlen = strlen(name);

        char* buf = lockBuffer(s, len+1+newlen);

        // insert a '/' if needed
        if (buf[len-1] != OS_PATH_SEPARATOR)
            buf[len++] = OS_PATH_SEPARATOR;

        memcpy(buf+len, name, newlen+1);
        len += newlen;

        unlockBuffer(s, buf, len);

        return s;
    } else {
        priv_setPathName(s, name);
        return s;
    }
}

inline std::string& appendPathCopy(std::string s, const char* name) {
    return appendPath(s, name);
}

inline std::string& appendPath(std::string& s, const String8& leaf) {
    return appendPath(s, leaf.c_str());
}

inline std::string& appendPathCopy(std::string s, const String8& leaf) {
    return appendPath(s, leaf);
}

inline String8 getPathLeaf(const std::string& s) {
    const char* cp;
    const char*const buf = s.c_str();

    cp = strrchr(buf, OS_PATH_SEPARATOR);
    if (cp == nullptr)
        return s;
    else
        return cp+1;
}

inline char* find_extension(const std::string& s)
{
    const char* lastSlash;
    const char* lastDot;
    const char* const str = s.c_str();

    // only look at the filename
    lastSlash = strrchr(str, OS_PATH_SEPARATOR);
    if (lastSlash == nullptr)
        lastSlash = str;
    else
        lastSlash++;

    // find the last dot
    lastDot = strrchr(lastSlash, '.');
    if (lastDot == nullptr)
        return nullptr;

    // looks good, ship it
    return const_cast<char*>(lastDot);
}

inline String8 getPathExtension(const std::string& s)
{
    char* ext;

    ext = find_extension(s);
    if (ext != nullptr)
        return ext;
    else
        return "";
}

inline String8 getBasePath(const std::string& s)
{
    char* ext;
    const char* const str = s.c_str();

    ext = find_extension(s);
    if (ext == nullptr)
        return s;
    else
        return std::string(str, ext - str);
}

inline std::u16string s2ws(const std::string& str) {
    // TODO: use utf8_to_utf16
    using convert_typeX = std::codecvt_utf8<char16_t>;
    std::wstring_convert<convert_typeX, char16_t> converterX;

    return converterX.from_bytes(str);
}

inline std::string ws2s(const std::u16string& wstr) {
    // TODO: use utf16_to_utf8
    using convert_typeX = std::codecvt_utf8<char16_t>;
    std::wstring_convert<convert_typeX, char16_t> converterX;

    return converterX.to_bytes(wstr);
}

inline String8 toString8() {
    return "";
}

inline String8 toString8(String8 s) {
    return s;
}

inline String8 toString8(String16 s) {
    return ws2s(s);
}

inline String8 toString8(const char* s) {
    return std::string(s);
}

inline String8 toString8(const char* s, size_t len) {
    return std::string(s, len);
}

inline String8 toString8(const char16_t* s, size_t len) {
    return ws2s(std::u16string(s, len));
}

}  // namespace android

#else
#ifndef ANDROID_STRING8_H
#define ANDROID_STRING8_H

#include <iostream>
#include <string>

#include <utils/Errors.h>
#include <utils/Unicode.h>
#include <utils/TypeHelpers.h>

#include <string.h> // for strcmp
#include <stdarg.h>

// ---------------------------------------------------------------------------

namespace android {

class String16;

// DO NOT USE: please use std::string

//! This is a string holding UTF-8 characters. Does not allow the value more
// than 0x10FFFF, which is not valid unicode codepoint.
class String8
{
public:
                                String8();
                                String8(const String8& o);
    explicit                    String8(const char* o);
    explicit                    String8(const char* o, size_t numChars);

    explicit                    String8(const String16& o);
    explicit                    String8(const char16_t* o);
    explicit                    String8(const char16_t* o, size_t numChars);
    explicit                    String8(const char32_t* o);
    explicit                    String8(const char32_t* o, size_t numChars);
                                ~String8();

    static String8              format(const char* fmt, ...) __attribute__((format (printf, 1, 2)));
    static String8              formatV(const char* fmt, va_list args);

    inline  const char*         c_str() const;

private:
    // These symbols are for potential backward compatibility with prebuilts. To be removed.
    inline  const char*         string() const;
    static inline std::string   std_string(const String8& str);
    inline  bool                isEmpty() const;
public:

    inline  size_t              size() const;
    inline  size_t              bytes() const;
    inline  bool                empty() const;

            size_t              length() const;

            void                clear();

            void                setTo(const String8& other);
            status_t            setTo(const char* other);
            status_t            setTo(const char* other, size_t numChars);
            status_t            setTo(const char16_t* other, size_t numChars);
            status_t            setTo(const char32_t* other,
                                      size_t length);

            status_t            append(const String8& other);
            status_t            append(const char* other);
            status_t            append(const char* other, size_t numChars);

            status_t            appendFormat(const char* fmt, ...)
                    __attribute__((format (printf, 2, 3)));
            status_t            appendFormatV(const char* fmt, va_list args);

    inline  String8&            operator=(const String8& other);
    inline  String8&            operator=(const char* other);

    inline  String8&            operator+=(const String8& other);
    inline  String8             operator+(const String8& other) const;

    inline  String8&            operator+=(const char* other);
    inline  String8             operator+(const char* other) const;

    inline  int                 compare(const String8& other) const;

    inline  bool                operator<(const String8& other) const;
    inline  bool                operator<=(const String8& other) const;
    inline  bool                operator==(const String8& other) const;
    inline  bool                operator!=(const String8& other) const;
    inline  bool                operator>=(const String8& other) const;
    inline  bool                operator>(const String8& other) const;

    inline  bool                operator<(const char* other) const;
    inline  bool                operator<=(const char* other) const;
    inline  bool                operator==(const char* other) const;
    inline  bool                operator!=(const char* other) const;
    inline  bool                operator>=(const char* other) const;
    inline  bool                operator>(const char* other) const;

    inline                      operator const char*() const;

            char*               lockBuffer(size_t size);
            void                unlockBuffer();
            status_t            unlockBuffer(size_t size);

            // return the index of the first byte of other in this at or after
            // start, or -1 if not found
            ssize_t             find(const char* other, size_t start = 0) const;

            // return true if this string contains the specified substring
    inline  bool                contains(const char* other) const;

            // removes all occurrence of the specified substring
            // returns true if any were found and removed
            bool                removeAll(const char* other);

            void                toLower();


    /*
     * These methods operate on the string as if it were a path name.
     */

    /*
     * Get just the filename component.
     *
     * "/tmp/foo/bar.c" --> "bar.c"
     */
    String8 getPathLeaf(void) const;

    /*
     * Remove the last (file name) component, leaving just the directory
     * name.
     *
     * "/tmp/foo/bar.c" --> "/tmp/foo"
     * "/tmp" --> "" // ????? shouldn't this be "/" ???? XXX
     * "bar.c" --> ""
     */
    String8 getPathDir(void) const;

    /*
     * Retrieve the front (root dir) component.  Optionally also return the
     * remaining components.
     *
     * "/tmp/foo/bar.c" --> "tmp" (remain = "foo/bar.c")
     * "/tmp" --> "tmp" (remain = "")
     * "bar.c" --> "bar.c" (remain = "")
     */
    String8 walkPath(String8* outRemains = nullptr) const;

    /*
     * Return the filename extension.  This is the last '.' and any number
     * of characters that follow it.  The '.' is included in case we
     * decide to expand our definition of what constitutes an extension.
     *
     * "/tmp/foo/bar.c" --> ".c"
     * "/tmp" --> ""
     * "/tmp/foo.bar/baz" --> ""
     * "foo.jpeg" --> ".jpeg"
     * "foo." --> ""
     */
    String8 getPathExtension(void) const;

    /*
     * Return the path without the extension.  Rules for what constitutes
     * an extension are described in the comment for getPathExtension().
     *
     * "/tmp/foo/bar.c" --> "/tmp/foo/bar"
     */
    String8 getBasePath(void) const;

    /*
     * Add a component to the pathname.  We guarantee that there is
     * exactly one path separator between the old path and the new.
     * If there is no existing name, we just copy the new name in.
     *
     * If leaf is a fully qualified path (i.e. starts with '/', it
     * replaces whatever was there before.
     */
    String8& appendPath(const char* leaf);
    String8& appendPath(const String8& leaf) { return appendPath(leaf.c_str()); }

    /*
     * Like appendPath(), but does not affect this string.  Returns a new one instead.
     */
    String8 appendPathCopy(const char* leaf) const
                                             { String8 p(*this); p.appendPath(leaf); return p; }
    String8 appendPathCopy(const String8& leaf) const { return appendPathCopy(leaf.c_str()); }

    /*
     * Converts all separators in this string to /, the default path separator.
     *
     * If the default OS separator is backslash, this converts all
     * backslashes to slashes, in-place. Otherwise it does nothing.
     * Returns self.
     */
    String8& convertToResPath();

private:
            status_t            real_append(const char* other, size_t numChars);
            char*               find_extension(void) const;

            const char* mString;
};

// String8 can be trivially moved using memcpy() because moving does not
// require any change to the underlying SharedBuffer contents or reference count.
ANDROID_TRIVIAL_MOVE_TRAIT(String8)

static inline std::ostream& operator<<(std::ostream& os, const String8& str) {
    os << str.c_str();
    return os;
}

// ---------------------------------------------------------------------------
// No user servicable parts below.

inline int compare_type(const String8& lhs, const String8& rhs)
{
    return lhs.compare(rhs);
}

inline int strictly_order_type(const String8& lhs, const String8& rhs)
{
    return compare_type(lhs, rhs) < 0;
}

inline const char* String8::c_str() const
{
    return mString;
}
inline const char* String8::string() const
{
    return mString;
}

inline std::string String8::std_string(const String8& str)
{
    return std::string(str.c_str());
}

inline size_t String8::size() const
{
    return length();
}

inline bool String8::empty() const
{
    return length() == 0;
}

inline bool String8::isEmpty() const
{
    return length() == 0;
}

inline size_t String8::bytes() const
{
    return length();
}

inline bool String8::contains(const char* other) const
{
    return find(other) >= 0;
}

inline String8& String8::operator=(const String8& other)
{
    setTo(other);
    return *this;
}

inline String8& String8::operator=(const char* other)
{
    setTo(other);
    return *this;
}

inline String8& String8::operator+=(const String8& other)
{
    append(other);
    return *this;
}

inline String8 String8::operator+(const String8& other) const
{
    String8 tmp(*this);
    tmp += other;
    return tmp;
}

inline String8& String8::operator+=(const char* other)
{
    append(other);
    return *this;
}

inline String8 String8::operator+(const char* other) const
{
    String8 tmp(*this);
    tmp += other;
    return tmp;
}

inline int String8::compare(const String8& other) const
{
    return strcmp(mString, other.mString);
}

inline bool String8::operator<(const String8& other) const
{
    return strcmp(mString, other.mString) < 0;
}

inline bool String8::operator<=(const String8& other) const
{
    return strcmp(mString, other.mString) <= 0;
}

inline bool String8::operator==(const String8& other) const
{
    return strcmp(mString, other.mString) == 0;
}

inline bool String8::operator!=(const String8& other) const
{
    return strcmp(mString, other.mString) != 0;
}

inline bool String8::operator>=(const String8& other) const
{
    return strcmp(mString, other.mString) >= 0;
}

inline bool String8::operator>(const String8& other) const
{
    return strcmp(mString, other.mString) > 0;
}

inline bool String8::operator<(const char* other) const
{
    return strcmp(mString, other) < 0;
}

inline bool String8::operator<=(const char* other) const
{
    return strcmp(mString, other) <= 0;
}

inline bool String8::operator==(const char* other) const
{
    return strcmp(mString, other) == 0;
}

inline bool String8::operator!=(const char* other) const
{
    return strcmp(mString, other) != 0;
}

inline bool String8::operator>=(const char* other) const
{
    return strcmp(mString, other) >= 0;
}

inline bool String8::operator>(const char* other) const
{
    return strcmp(mString, other) > 0;
}

inline String8::operator const char*() const
{
    return mString;
}

}  // namespace android

// ---------------------------------------------------------------------------

#endif // ANDROID_STRING8_H
#endif
