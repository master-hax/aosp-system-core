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

#ifndef _LIBS_LOG_LOG_H
#define _LIBS_LOG_LOG_H

/*
 * Special case for __ANDROID_USE_LIBLOG_MACRO_INTERFACE since available
 * since epoch internally.
 */

#ifdef __ANDROID_USE_LIBLOG_MACRO_INTERFACE
#if __ANDROID_USE_LIBLOG_MACRO_INTERFACE
/* Already included android/log.h correctly */
#else
/* Re-include android/log.h with a correction */
#undef __ANDROID_USE_LIBLOG_MACRO_INTERFACE
#define __ANDROID_USE_LIBLOG_MACRO_INTERFACE 1
#undef _ANDROID_LOG_H
#include <android/log.h>
#endif
#else
/* Including android/log.h for first time */
#define __ANDROID_USE_LIBLOG_MACRO_INTERFACE 1
#include <android/log.h>
#endif

#endif /* _LIBS_LOG_LOG_H */
