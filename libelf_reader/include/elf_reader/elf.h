/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_ELF_H_
#define ANDROID_ELF_H_

#if defined(__linux__)
#include <elf.h>

#ifndef EM_AARCH64
#define EM_AARCH64  183
#endif

#else

#include <inttypes.h>

using __u16 = uint16_t;
using __u32 = uint32_t;
using __u64 = uint64_t;
using __s16 = int16_t;
using __s32 = int32_t;
using __s64 = int64_t;

#include "../../../bionic/libc/kernel/uapi/linux/elf.h"
#endif

#endif  // ANDROID_ELF_H_
