/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <stdint.h>

__BEGIN_DECLS

// For host builds, __INTRODUCED_IN is not defined.
#ifndef __INTRODUCED_IN
#define __INTRODUCED_IN(x)
#endif

#if __ANDROID_API__ >= __ANDROID_API_Q__

struct ACgroupController;
typedef struct ACgroupController ACgroupController;

// ACgroupFile

/**
 * Do necessary initialization. Return true if successful, false otherwise.
 * This is NOT thread-safe.
 */
__attribute__((warn_unused_result)) bool ACgroupFile_init() __INTRODUCED_IN(29);

/**
 * Return file version.
 * If ACgroupFile_init() isn't called, initialization will be done first.
 * If initialization failed, return 0.
 */
__attribute__((warn_unused_result)) uint32_t ACgroupFile_getVersion() __INTRODUCED_IN(29);

/**
 * Return the number of controller.
 * If ACgroupFile_init() isn't called, initialization will be done first.
 * If initialization failed, return 0.
 */
__attribute__((warn_unused_result)) uint32_t ACgroupFile_getControllerCount() __INTRODUCED_IN(29);

/**
 * Return the controller at the given index.
 * Returns nullptr if the given index exceeds getControllerCount().
 * If ACgroupFile_init() isn't called, initialization will be done first.
 * If initialization failed, return 0.
 */
__attribute__((warn_unused_result)) const ACgroupController* ACgroupFile_getController(
        uint32_t index) __INTRODUCED_IN(29);

// ACgroupController

/**
 * Return the version of the given controller.
 * If the given controller is null, return 0.
 */
__attribute__((warn_unused_result)) uint32_t ACgroupController_getVersion(const ACgroupController*)
        __INTRODUCED_IN(29);

/**
 * Return the name of the given controller.
 * If the given controller is null, return nullptr.
 */
__attribute__((warn_unused_result)) const char* ACgroupController_getName(const ACgroupController*)
        __INTRODUCED_IN(29);

/**
 * Return the path of the given controller.
 * If the given controller is null, return nullptr.
 */
__attribute__((warn_unused_result)) const char* ACgroupController_getPath(const ACgroupController*)
        __INTRODUCED_IN(29);

__END_DECLS

#endif
