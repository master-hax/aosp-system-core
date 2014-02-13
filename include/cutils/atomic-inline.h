/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef ANDROID_CUTILS_ATOMIC_INLINE_H
#define ANDROID_CUTILS_ATOMIC_INLINE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Inline declarations and macros for some special-purpose atomic
 * operations.  These are intended for rare circumstances where a
 * memory barrier needs to be issued inline rather than as a function
 * call.
 *
 * Most code should not use these.
 *
 * Anything that does include this file must set ANDROID_SMP to either
 * 0 or 1, indicating compilation for UP or SMP, respectively.
 *
 * Macros defined in this header:
 *
 * void ANDROID_MEMBAR_FULL(void)
 *   Full memory barrier.  Provides a compiler reordering barrier, and
 *   on SMP systems emits an appropriate instruction.
 */

#if !defined(ANDROID_SMP)
# error "Must define ANDROID_SMP before including atomic-inline.h"
#endif

#if defined(__aarch64__)
#include <cutils/atomic-arm64.h>
#elif defined(__arm__)
#include <cutils/atomic-arm.h>
#elif defined(__i386__)
#include <cutils/atomic-x86.h>
#elif defined(__x86_64__)
#include <cutils/atomic-x86_64.h>
#elif defined(__mips__)
#include <cutils/atomic-mips.h>
#else
#error atomic operations are unsupported
#endif

#if ANDROID_SMP == 0
#define ANDROID_MEMBAR_FULL android_compiler_barrier
#else
#define ANDROID_MEMBAR_FULL android_memory_barrier
#endif

#if ANDROID_SMP == 0
#define ANDROID_MEMBAR_STORE android_compiler_barrier
#else
#define ANDROID_MEMBAR_STORE android_memory_store_barrier
#endif

#ifdef __LP64__

extern ANDROID_ATOMIC_INLINE
void* android_atomic_acquire_load_pointer(volatile const void** ptr)
{
    return (void*)android_atomic_acquire_load64((volatile const int64_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void* android_atomic_release_load_pointer(volatile const void** ptr)
{
    return (void*)android_atomic_release_load64((volatile const int64_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void android_atomic_acquire_store_pointer(void* value, volatile void** ptr)
{
    android_atomic_acquire_store64((int64_t)value, (volatile int64_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void android_atomic_release_store_pointer(void* value, volatile void** ptr)
{
    android_atomic_release_store64((int64_t)value, (volatile int64_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void* android_atomic_cas_pointer(void* old_value, void* new_value,
                                 volatile void** ptr)
{
    return (void*)android_atomic_cas64((int64_t)old_value, (int64_t)new_value,
                                       (volatile int64_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void* android_atomic_acquire_cas_pointer(void* old_value, void* new_value,
                                         volatile void** ptr)
{
    return (void*)android_atomic_acquire_cas64((int64_t)old_value,
                                               (int64_t)new_value,
                                               (volatile int64_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void* android_atomic_release_cas_pointer(void* old_value, void* new_value,
                                         volatile void** ptr)
{
    return (void*)android_atomic_release_cas64((int64_t)old_value,
                                               (int64_t)new_value,
                                               (volatile int64_t*)ptr);
}

#else /* #ifdef __LP64__ */

extern ANDROID_ATOMIC_INLINE
void* android_atomic_acquire_load_pointer(volatile const void** ptr)
{
    return (void*)android_atomic_acquire_load((volatile const int32_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void* android_atomic_release_load_pointer(volatile const void** ptr)
{
    return (void*)android_atomic_release_load((volatile const int32_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void android_atomic_acquire_store_pointer(void* value, volatile void** ptr)
{
    android_atomic_acquire_store((int32_t)value, (volatile int32_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void android_atomic_release_store_pointer(void* value, volatile void** ptr)
{
    android_atomic_release_store((int32_t)value, (volatile int32_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void* android_atomic_cas_pointer(void* old_value, void* new_value,
                                 volatile void** ptr)
{
    return (void*)android_atomic_cas((int32_t)old_value, (int32_t)new_value,
                                     (volatile int32_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void* android_atomic_acquire_cas_pointer(void* old_value, void* new_value,
                                         volatile void** ptr)
{
    return (void*)android_atomic_acquire_cas((int32_t)old_value,
                                             (int32_t)new_value,
                                             (volatile int32_t*)ptr);
}

extern ANDROID_ATOMIC_INLINE
void* android_atomic_release_cas_pointer(void* old_value, void* new_value,
                                         volatile void** ptr)
{
    return (void*)android_atomic_release_cas((int32_t)old_value,
                                             (int32_t)new_value,
                                             (volatile int32_t*)ptr);
}

#endif /* #ifdef __LP64__ */

#ifdef __cplusplus
}
#endif

#endif /* ANDROID_CUTILS_ATOMIC_INLINE_H */
