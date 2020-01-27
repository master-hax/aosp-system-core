/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef ANDROID_CUTILS_STDATOMIC_H
#define ANDROID_CUTILS_STDATOMIC_H

/*
 * This header can be used to avoid conflicts between C <stdatomic.h> and C++ <atomic>. From C it
 * simply includes <stdatomic.h>, while from C++ it acts as an implementation of <stdatomic.h> in
 * C++ as proposed in wg21.link/p0943 which will probably be part of C++23.
 *
 * It is only necessary to include this header from headers that may be compiled for the host and
 * may be included from either C or C++. In device-only code, Bionic's <stdatomic.h> provides
 * similar functionality, and in C/C++ source files and C++ only headers, the <stdatomic.h> or
 * <atomic> headers can be used directly.
 */

#if defined(__cplusplus) && __has_include(<atomic>)

#include <atomic>
#define _Atomic(T) std::atomic<T>

using std::memory_order;
using std::memory_order_relaxed;
using std::memory_order_consume;
using std::memory_order_acquire;
using std::memory_order_release;
using std::memory_order_acq_rel;
using std::memory_order_seq_cst;

using std::atomic_flag;

using std::atomic_bool;
using std::atomic_char;
using std::atomic_schar;
using std::atomic_uchar;
using std::atomic_short;
using std::atomic_ushort;
using std::atomic_int;
using std::atomic_uint;
using std::atomic_long;
using std::atomic_ulong;
using std::atomic_llong;
using std::atomic_ullong;
// TODO(pcc): Add "using std::atomic_char8_t;" here once libc++ defines it.
using std::atomic_char16_t;
using std::atomic_char32_t;
using std::atomic_wchar_t;
using std::atomic_int8_t;
using std::atomic_uint8_t;
using std::atomic_int16_t;
using std::atomic_uint16_t;
using std::atomic_int32_t;
using std::atomic_uint32_t;
using std::atomic_int64_t;
using std::atomic_uint64_t;
using std::atomic_int_least8_t;
using std::atomic_uint_least8_t;
using std::atomic_int_least16_t;
using std::atomic_uint_least16_t;
using std::atomic_int_least32_t;
using std::atomic_uint_least32_t;
using std::atomic_int_least64_t;
using std::atomic_uint_least64_t;
using std::atomic_int_fast8_t;
using std::atomic_uint_fast8_t;
using std::atomic_int_fast16_t;
using std::atomic_uint_fast16_t;
using std::atomic_int_fast32_t;
using std::atomic_uint_fast32_t;
using std::atomic_int_fast64_t;
using std::atomic_uint_fast64_t;
using std::atomic_intptr_t;
using std::atomic_uintptr_t;
using std::atomic_size_t;
using std::atomic_ptrdiff_t;
using std::atomic_intmax_t;
using std::atomic_uintmax_t;

#else
#include <stdatomic.h>
#endif

#endif // ANDROID_CUTILS_STDATOMIC_H
