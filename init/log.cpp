/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <stdlib.h>
#include <string.h>

#include <selinux/selinux.h>

#include "log.h"

void init_klog_write(int level, const char* fmt, ...) {
    // TODO: use a single write.
    klog_write(level, "<%d>%s: ", level, basename(getprogname()));
    va_list ap;
    va_start(ap, fmt);
    klog_vwrite(level, fmt, ap);
    va_end(ap);
}

int selinux_klog_callback(int type, const char *fmt, ...) {
    int level;
    va_list ap;
    switch (type) {
    case SELINUX_WARNING:
        level = KLOG_WARNING_LEVEL;
        break;
    case SELINUX_INFO:
        level = KLOG_INFO_LEVEL;
        break;
    default:
        level = KLOG_ERROR_LEVEL;
        break;
    }
    va_start(ap, fmt);
    klog_vwrite(level, fmt, ap);
    va_end(ap);
    return 0;
}
