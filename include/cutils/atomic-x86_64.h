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

#ifndef ANDROID_CUTILS_ATOMIC_X86_64_H
#define ANDROID_CUTILS_ATOMIC_X86_64_H

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

#include <cutils/atomic-x86_64_64.h>
#include <cutils/atomic-x86_64_32.h>

#endif /* ANDROID_CUTILS_ATOMIC_X86_H */
