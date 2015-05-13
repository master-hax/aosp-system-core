/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef BASE_STRINGPRINTF_H
#define BASE_STRINGPRINTF_H

#include <stdarg.h>
#include <string>

namespace android {
namespace base {

// These printf-like functions are implemented in terms of vsnprintf, so they
// use the same attribute for compile-time format string checking. Using the
// attribute `gnu_printf' instead of `printf' on Windows allows z in %zd and
// PRIu64 and related to be recognized by the compile-time checking.

// Returns a string corresponding to printf-like formatting of the arguments.
std::string StringPrintf(const char* fmt, ...)
    __attribute__((__format__(gnu_printf, 1, 2)));

// Appends a printf-like formatting of the arguments to 'dst'.
void StringAppendF(std::string* dst, const char* fmt, ...)
    __attribute__((__format__(gnu_printf, 2, 3)));

// Appends a printf-like formatting of the arguments to 'dst'.
void StringAppendV(std::string* dst, const char* format, va_list ap)
    __attribute__((__format__(gnu_printf, 2, 0)));

}  // namespace base
}  // namespace android

#endif  // BASE_STRINGPRINTF_H
