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

#ifndef ANDROID_CUTILS_ATOMIC_X86_64_64_H
#define ANDROID_CUTILS_ATOMIC_X86_64_64_H

extern ANDROID_ATOMIC_INLINE long
android_atomic_acquire_load(volatile const long *ptr)
{
    long value = *ptr;
    android_compiler_barrier();
    return value;
}

extern ANDROID_ATOMIC_INLINE long
android_atomic_release_load(volatile const long *ptr)
{
    android_memory_barrier();
    return *ptr;
}

extern ANDROID_ATOMIC_INLINE void
android_atomic_acquire_store(long value, volatile long *ptr)
{
    *ptr = value;
    android_memory_barrier();
}

extern ANDROID_ATOMIC_INLINE void
android_atomic_release_store(long value, volatile long *ptr)
{
    android_compiler_barrier();
    *ptr = value;
}

extern ANDROID_ATOMIC_INLINE int
android_atomic_cas(long old_value, long new_value, volatile long *ptr)
{
    int32_t prev;
    __asm__ __volatile__ ("lock; cmpxchgq %1, %2"
                          : "=a" (prev)
                          : "q" (new_value), "m" (*ptr), "0" (old_value)
                          : "memory");
    return prev != old_value;
}

extern ANDROID_ATOMIC_INLINE int
android_atomic_acquire_cas(long old_value,
                           long new_value,
                           volatile long *ptr)
{
    /* Loads are not reordered with other loads. */
    return android_atomic_cas(old_value, new_value, ptr);
}

extern ANDROID_ATOMIC_INLINE int
android_atomic_release_cas(long old_value,
                           long new_value,
                           volatile long *ptr)
{
    /* Stores are not reordered with other stores. */
    return android_atomic_cas(old_value, new_value, ptr);
}

extern ANDROID_ATOMIC_INLINE long
android_atomic_add(long increment, volatile long *ptr)
{
    __asm__ __volatile__ ("lock; xaddq %0, %1"
                          : "+r" (increment), "+m" (*ptr)
                          : : "memory");
    /* increment now holds the old value of *ptr */
    return increment;
}

extern ANDROID_ATOMIC_INLINE long
android_atomic_inc(volatile long *addr)
{
    return android_atomic_add(1, addr);
}

extern ANDROID_ATOMIC_INLINE long
android_atomic_dec(volatile long *addr)
{
    return android_atomic_add(-1, addr);
}

extern ANDROID_ATOMIC_INLINE long
android_atomic_and(long value, volatile long *ptr)
{
    long prev, status;
    do {
        prev = *ptr;
        status = android_atomic_cas(prev, prev & value, ptr);
    } while (__builtin_expect(status != 0, 0));
    return prev;
}

extern ANDROID_ATOMIC_INLINE long
android_atomic_or(long value, volatile long *ptr)
{
    long prev, status;
    do {
        prev = *ptr;
        status = android_atomic_cas(prev, prev | value, ptr);
    } while (__builtin_expect(status != 0, 0));
    return prev;
}
#endif
