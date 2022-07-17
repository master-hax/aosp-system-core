/*
 * Copyright (C) 2022 The Android Open Source Project
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

/* clang-format off */
/* see the comment in lwt_sched.h about issues and the many clang-format bugs */

//  This header file facilitates building LWT with the Android build while
//  allowing it to be built externally with scripts on gLinux and adeb

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if defined(LWT_ARM64) || !defined(LWT_X64)
#define	LWT_NOT_ON_ANDROID
#define LWT_PTHREAD_SETAFFINITY
#endif

#if !defined(LWT_ARM64) && !defined(LWT_X64)
#define LWT_PTR_BITS	64
#define LWT_ARM64
#define LWT_CTX_ARRAY
#define LWT_CPU_PTHREAD_KEY
#define LWT_MP
// #define LWT_SMT
// #define LWT_FIXED_ADDRESSES
// #define LWT_X64
#define LWT_DEBUG
// #define LWT_BITS
#endif

