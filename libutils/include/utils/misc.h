/*
 * Copyright (C) 2005 The Android Open Source Project
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

//
// Handy utility functions and portability code.
//
#ifndef _LIBS_UTILS_MISC_H
#define _LIBS_UTILS_MISC_H

#include <utils/Endian.h>

/* get #of elements in a static array
 * DO NOT USE: please use std::vector/std::array instead
 */
#ifndef NELEM
# define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))
#endif

namespace android {

typedef void (*sysprop_change_callback)(void);

/* 'cb' will be called (in order of highest 'priority' first) whenever report_sysprop_change is
 * called
 *
 * DO NOT USE: This should only ever be used when it is required in order to mesh with existing uses
 * of this API. For new use, there are several preferred ways of doing this:
 * - libbase's WaitForProperty/WaitForPropertyCreation APIs
 * - creating callbacks with semantic meanings (example: 'addMyCallback')
 */
void add_sysprop_change_callback(sysprop_change_callback cb, int priority);
/* Calls all 'cb' registered with add_sysprop_change_callback within the same process. This happens
 * synchronously.
 */
void report_sysprop_change();

}  // namespace android

#endif // _LIBS_UTILS_MISC_H
