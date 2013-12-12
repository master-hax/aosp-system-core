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


#ifndef UTILS_LOOPER_COMMON_H
#define UTILS_LOOPER_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

enum {
    /**
     * Option for ALooper_prepare: this looper will accept calls to
     * ALooper_addFd() that do not have a callback (that is provide NULL
     * for the callback).  In this case the caller of ALooper_pollOnce()
     * or ALooper_pollAll() MUST check the return from these functions to
     * discover when data is available on such fds and process it.
     */
    ALOOPER_PREPARE_ALLOW_NON_CALLBACKS = 1<<0
};

enum {
    /**
     * Result from ALooper_pollOnce() and ALooper_pollAll():
     * The poll was awoken using wake() before the timeout expired
     * and no callbacks were executed and no other file descriptors were ready.
     */
    ALOOPER_POLL_WAKE = -1,

    /**
     * Result from ALooper_pollOnce() and ALooper_pollAll():
     * One or more callbacks were executed.
     */
    ALOOPER_POLL_CALLBACK = -2,

    /**
     * Result from ALooper_pollOnce() and ALooper_pollAll():
     * The timeout expired.
     */
    ALOOPER_POLL_TIMEOUT = -3,

    /**
     * Result from ALooper_pollOnce() and ALooper_pollAll():
     * An error occurred.
     */
    ALOOPER_POLL_ERROR = -4,
};

/**
 * Flags for file descriptor events that a looper can monitor.
 *
 * These flag bits can be combined to monitor multiple events at once.
 */
enum {
    /**
     * The file descriptor is available for read operations.
     */
    ALOOPER_EVENT_INPUT = 1 << 0,

    /**
     * The file descriptor is available for write operations.
     */
    ALOOPER_EVENT_OUTPUT = 1 << 1,

    /**
     * The file descriptor has encountered an error condition.
     *
     * The looper always sends notifications about errors; it is not necessary
     * to specify this event flag in the requested event set.
     */
    ALOOPER_EVENT_ERROR = 1 << 2,

    /**
     * The file descriptor was hung up.
     * For example, indicates that the remote end of a pipe or socket was closed.
     *
     * The looper always sends notifications about hangups; it is not necessary
     * to specify this event flag in the requested event set.
     */
    ALOOPER_EVENT_HANGUP = 1 << 3,

    /**
     * The file descriptor is invalid.
     * For example, the file descriptor was closed prematurely.
     *
     * The looper always sends notifications about invalid file descriptors; it is not necessary
     * to specify this event flag in the requested event set.
     */
    ALOOPER_EVENT_INVALID = 1 << 4,
};

/**
 * For callback-based event loops, this is the prototype of the function
 * that is called when a file descriptor event occurs.
 * It is given the file descriptor it is associated with,
 * a bitmask of the poll events that were triggered (typically ALOOPER_EVENT_INPUT),
 * and the data pointer that was originally supplied.
 *
 * Implementations should return 1 to continue receiving callbacks, or 0
 * to have this file descriptor and callback unregistered from the looper.
 */
typedef int (*ALooper_callbackFunc)(int fd, int events, void* data);

#ifdef __cplusplus
};
#endif

#endif // UTILS_LOOPER_COMMON_H
