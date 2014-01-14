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

#ifndef ANDROID_CUTILS_ATOMIC_X86_H
#define ANDROID_CUTILS_ATOMIC_X86_H

#include <stdint.h>

#ifndef ANDROID_ATOMIC_INLINE
#define ANDROID_ATOMIC_INLINE inline __attribute__((always_inline))
#endif

extern ANDROID_ATOMIC_INLINE void android_compiler_barrier(void)
{
    __asm__ __volatile__ ("" : : : "memory");
}

#if ANDROID_SMP == 0
extern ANDROID_ATOMIC_INLINE void android_memory_barrier(void)
{
    android_compiler_barrier();
}
extern ANDROID_ATOMIC_INLINE void android_memory_store_barrier(void)
{
    android_compiler_barrier();
}
#else
extern ANDROID_ATOMIC_INLINE void android_memory_barrier(void)
{
    __asm__ __volatile__ ("mfence" : : : "memory");
}
extern ANDROID_ATOMIC_INLINE void android_memory_store_barrier(void)
{
    android_compiler_barrier();
}
#endif

extern ANDROID_ATOMIC_INLINE int32_t
android_atomic_acquire_load(volatile const int32_t *ptr)
{
    int32_t value = *ptr;
    android_compiler_barrier();
    return value;
}

extern ANDROID_ATOMIC_INLINE int32_t
android_atomic_release_load(volatile const int32_t *ptr)
{
    android_memory_barrier();
    return *ptr;
}

extern ANDROID_ATOMIC_INLINE void
android_atomic_acquire_store(int32_t value, volatile int32_t *ptr)
{
    *ptr = value;
    android_memory_barrier();
}

extern ANDROID_ATOMIC_INLINE void
android_atomic_release_store(int32_t value, volatile int32_t *ptr)
{
    android_compiler_barrier();
    *ptr = value;
}

extern ANDROID_ATOMIC_INLINE int
android_atomic_cas(int32_t old_value, int32_t new_value, volatile int32_t *ptr)
{
    int32_t prev;
    __asm__ __volatile__ ("lock; cmpxchgl %1, %2"
                          : "=a" (prev)
                          : "q" (new_value), "m" (*ptr), "0" (old_value)
                          : "memory");
    return prev != old_value;
}

extern ANDROID_ATOMIC_INLINE int
android_atomic_acquire_cas(int32_t old_value,
                           int32_t new_value,
                           volatile int32_t *ptr)
{
    /* Loads are not reordered with other loads. */
    return android_atomic_cas(old_value, new_value, ptr);
}

extern ANDROID_ATOMIC_INLINE int
android_atomic_release_cas(int32_t old_value,
                           int32_t new_value,
                           volatile int32_t *ptr)
{
    /* Stores are not reordered with other stores. */
    return android_atomic_cas(old_value, new_value, ptr);
}

extern ANDROID_ATOMIC_INLINE int32_t
android_atomic_add(int32_t increment, volatile int32_t *ptr)
{
    __asm__ __volatile__ ("lock; xaddl %0, %1"
                          : "+r" (increment), "+m" (*ptr)
                          : : "memory");
    /* increment now holds the old value of *ptr */
    return increment;
}

extern ANDROID_ATOMIC_INLINE int32_t
android_atomic_inc(volatile int32_t *addr)
{
    return android_atomic_add(1, addr);
}

extern ANDROID_ATOMIC_INLINE int32_t
android_atomic_dec(volatile int32_t *addr)
{
    return android_atomic_add(-1, addr);
}

extern ANDROID_ATOMIC_INLINE int32_t
android_atomic_and(int32_t value, volatile int32_t *ptr)
{
    int32_t prev, status;
    do {
        prev = *ptr;
        status = android_atomic_cas(prev, prev & value, ptr);
    } while (__builtin_expect(status != 0, 0));
    return prev;
}

extern ANDROID_ATOMIC_INLINE int32_t
android_atomic_or(int32_t value, volatile int32_t *ptr)
{
    int32_t prev, status;
    do {
        prev = *ptr;
        status = android_atomic_cas(prev, prev | value, ptr);
    } while (__builtin_expect(status != 0, 0));
    return prev;
}

#define android_atomic32_inc android_atomic_inc
#define android_atomic32_dec android_atomic_dec
#define android_atomic32_add android_atomic_add
#define android_atomic32_and android_atomic_and
#define android_atomic32_or  android_atomic_or
#define android_atomic32_acquire_load android_atomic_acquire_load
#define android_atomic32_release_load android_atomic_release_load
#define android_atomic32_acquire_store android_atomic_acquire_store
#define android_atomic32_release_store android_atomic_release_store
#define android_atomic32_acquire_cas android_atomic_acquire_cas
#define android_atomic32_release_cas android_atomic_release_cas
#define android_atomic32_write android_atomic32_release_store
#define android_atomic32_cmpxchg android_atomic32_release_cas
#define android_atomic32_cas android_atomic_cas

#endif /* ANDROID_CUTILS_ATOMIC_X86_H */
