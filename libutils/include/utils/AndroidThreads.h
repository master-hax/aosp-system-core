/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef _LIBS_UTILS_ANDROID_THREADS_H
#define _LIBS_UTILS_ANDROID_THREADS_H

#include <stdint.h>
#include <sys/types.h>

#if !defined(_WIN32)
# include <pthread.h>
#endif

#include <utils/ThreadDefs.h>

// ---------------------------------------------------------------------------
// C API

#ifdef __cplusplus
extern "C" {
#endif

// Create and run a new thread.
extern int androidCreateThread(android_thread_func_t, void *);

// Create thread with lots of parameters
extern int androidCreateThreadEtc(android_thread_func_t entryFunction,
                                  void *userData,
                                  const char* threadName,
                                  int32_t threadPriority,
                                  size_t threadStackSize,
                                  android_thread_id_t *threadId);

// Get some sort of unique identifier for the current thread.
extern android_thread_id_t androidGetThreadId();

// set the same of the running thread
extern void androidSetThreadName(const char* name);

// ------------------------------------------------------------------
// Extra functions working with raw pids.

#if defined(__ANDROID__)
// Change the priority AND scheduling group of a particular thread.  The priority
// should be one of the ANDROID_PRIORITY constants.  Returns INVALID_OPERATION
// if the priority set failed, else another value if just the group set failed;
// in either case errno is set.  Thread ID zero means current thread.
extern int androidSetThreadPriority(pid_t tid, int prio);

// Get the current priority of a particular thread. Returns one of the
// ANDROID_PRIORITY constants or a negative result in case of error.
extern int androidGetThreadPriority(pid_t tid);
#endif

#ifdef __cplusplus
} // extern "C"
#endif

// ----------------------------------------------------------------------------
// C++ API
#ifdef __cplusplus
namespace android {
// ----------------------------------------------------------------------------

// Create and run a new thread.
inline bool createThread(thread_func_t f, void *a) {
    return androidCreateThread(f, a) ? true : false;
}

// Create thread with lots of parameters
inline bool createThreadEtc(thread_func_t entryFunction,
                            void *userData,
                            const char* threadName = "android:unnamed_thread",
                            int32_t threadPriority = PRIORITY_DEFAULT,
                            size_t threadStackSize = 0,
                            thread_id_t *threadId = nullptr)
{
    return androidCreateThreadEtc(entryFunction, userData, threadName,
        threadPriority, threadStackSize, threadId) ? true : false;
}

// Get some sort of unique identifier for the current thread.
inline thread_id_t getThreadId() {
    return androidGetThreadId();
}

#if !defined(_WIN32)

typedef int (*thread_hook_t)(void*, const char*);

// Right after a thread is created, androidCreateRawThreadEtc ensures that
// hook(userdata, threadName) runs on the new thread before the entry function.
// If hook(userdata, threadName) returns non-zero value, the thread will
// terminate early without executing the entryFunction or the post hook.
// Note: this conflicts with androidSetCreateThreadFunc.
// Note: this function itself is not thread-safe.
void setThreadPreHook(thread_hook_t hook, void* userdata);

// Returns the pre-hook set by androidSetThreadPreHook.
// Note: this function itself is not thread-safe.
void getThreadPreHook(thread_hook_t* hook, void** userdata);

// After the entry function ends, androidCreateRawThreadEtc ensures that
// hook(userdata, threadName) runs on the new thread.
// If the pre-hook passes, i.e. there are no pre-hook set or pre hook returns 0,
// regardless of the result of the entry function, the post-hook always runs.
// Note: this conflicts with androidSetCreateThreadFunc.
// Note: this function itself is not thread-safe.
void setThreadPostHook(thread_hook_t hook, void* userdata);

// Returns the post-hook set by androidSetThreadPostHook.
// Note: this function itself is not thread-safe.
void getThreadPostHook(thread_hook_t* hook, void** userdata);

#endif  // _WIN32

// ----------------------------------------------------------------------------
}  // namespace android
#endif  // __cplusplus
// ----------------------------------------------------------------------------

#endif // _LIBS_UTILS_ANDROID_THREADS_H
