/*
 * Copyright (C) 2016 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <cutils/android_get_control_file.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>

#include <android-base/macros.h> // for TEMP_FAILURE_RETRY on Darwin

#include "android_get_control_env.h"

#ifndef TEMP_FAILURE_RETRY_NULL
#define TEMP_FAILURE_RETRY_NULL(exp)                \
    ({                                              \
        __typeof__(exp) _rc;                        \
        do {                                        \
            _rc = (exp);                            \
        } while (_rc == nullptr && errno == EINTR); \
        _rc;                                        \
    })
#endif

LIBCUTILS_HIDDEN int __android_get_control_from_env(const char* prefix,
                                                    const char* name) {
    if (!prefix || !name) return -1;

    char *key = NULL;
    if (asprintf(&key, "%s%s", prefix, name) < 0) return -1;
    if (!key) return -1;

    char *cp = key;
    while (*cp) {
        if (!isalnum(*cp)) *cp = '_';
        ++cp;
    }

    const char* val = getenv(key);
    free(key);
    if (!val) return -1;

    errno = 0;
    long fd = strtol(val, NULL, 10);
    if (errno) return -1;

    // validity checking
    if ((fd < 0) || (fd > INT_MAX)) return -1;

    // Since we are inheriting an fd, it could legitimately exceed _SC_OPEN_MAX

    // Still open?
#if defined(F_GETFD) // Lowest overhead
    if (TEMP_FAILURE_RETRY(fcntl(fd, F_GETFD)) < 0) return -1;
#elif defined(F_GETFL) // Alternate lowest overhead
    if (TEMP_FAILURE_RETRY(fcntl(fd, F_GETFL)) < 0) return -1;
#else // Hail Mary pass
    struct stat s;
    if (TEMP_FAILURE_RETRY(fstat(fd, &s)) < 0) return -1;
#endif

    return static_cast<int>(fd);
}

int android_get_control_file(const char* path) {
    using char_ptr = std::unique_ptr<char, decltype(&free)>;
    // Try path, then realpath(path), as keys to get the fd from env.
    auto fd = __android_get_control_from_env(ANDROID_FILE_ENV_PREFIX, path);
    char_ptr given_path(nullptr, free);
    if (fd < 0) {
        given_path.reset(TEMP_FAILURE_RETRY_NULL(realpath(path, nullptr)));
        if (given_path == nullptr) return fd;
        fd = __android_get_control_from_env(ANDROID_FILE_ENV_PREFIX, given_path.get());
        if (fd < 0) return fd;
    }

#if defined(__linux__)
    // Find file path from /proc and make sure it is correct
    char* proc = nullptr;
    if (asprintf(&proc, "/proc/self/fd/%d", fd) < 0) return -1;
    if (!proc) return -1;
    char_ptr proc_ptr(proc, free);

    char_ptr fd_path(TEMP_FAILURE_RETRY_NULL(realpath(proc_ptr.get(), nullptr)), free);
    if (fd_path == nullptr) return -1;

    if (given_path == nullptr) {
        given_path.reset(TEMP_FAILURE_RETRY_NULL(realpath(path, nullptr)));
    }
    if (given_path == nullptr) return -1;

    if (strcmp(fd_path.get(), given_path.get()) != 0) return -1;
    // It is what we think it is
#endif

    return fd;
}
