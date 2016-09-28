/*
 * Copyright (C) 2005-2014 The Android Open Source Project
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

#ifndef _LIBS_CUTIL_LOG_H
#define _LIBS_CUTIL_LOG_H

/* We do not know if developer wanted log/log.h or subset android/log.h */
#include <log/log.h>

#if defined(__GNUC__)
#ifdef __USE_MINGW_ANSI_STDIO
#if __USE_MINGW_ANSI_STDIO
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-W#warnings"
#endif
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-W#warnings"
#endif
#endif
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpedantic"
#endif

#warning "Deprecated: don't include cutils/log.h, use either android/log.h or log/log.h"

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#if defined(__GNUC__)
#ifdef __USE_MINGW_ANSI_STDIO
#if __USE_MINGW_ANSI_STDIO
#else
#pragma GCC diagnostic pop
#endif
#else
#pragma GCC diagnostic pop
#endif
#endif

#endif /* _LIBS_CUTIL_LOG_H */
