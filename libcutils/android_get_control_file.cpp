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

// This file contains files implementation that can be shared between
// platforms as long as the correct headers are included.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cutils/android_get_control_file.h>
#include <cutils/sockets.h> // for __android_get_control_from_env()

int android_get_control_file(const char* path) {
    int fd = __android_get_control_from_env(ANDROID_FILE_ENV_PREFIX, path);

#if defined(__linux__)
    // Find file path from /proc and make sure it is correct
    char *proc = NULL;
    if (asprintf(&proc, "/proc/self/fd/%d", fd) < 0) return -1;
    if (!proc) return -1;

    size_t len = strlen(path);
    // readlink() does not guarantee a nul byte, len+2 so we catch truncation.
    char *buf = static_cast<char *>(calloc(1, len + 2));
    int save_errno = errno;
    if (!buf) {
        free(proc);
        errno = save_errno;
        return -1;
    }
    ssize_t ret = TEMP_FAILURE_RETRY(readlink(proc, buf, len + 1));
    save_errno = errno;
    free(proc);
    int cmp = (len != static_cast<size_t>(ret)) || strcmp(buf, path);
    free(buf);
    errno = save_errno;
    if (ret < 0) return -1;
    if (cmp != 0) return -1;
    // It is what we think it is
#endif

    return fd;
}
