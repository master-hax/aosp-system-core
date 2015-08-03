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

#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include <cutils/klog.h>
#include <selinux/selinux.h>

#include <base/stringprintf.h>

int SelinuxKlogCallback(int type, const char *fmt, ...) {
    std::string log_message;
    va_list ap;
    va_start(ap, fmt);
    android::base::StringAppendV(&log_message, fmt, ap);
    va_end(ap);
    if (type == SELINUX_WARNING) {
        LOG(WARNING) << log_message;
    } else if (type == SELINUX_INFO) {
        LOG(DEBUG) << log_message;
    } else {
        LOG(ERROR) << log_message;
    }
    return 0;
}

void KlogLogger(android::base::LogId id,
                android::base::LogSeverity severity,
                const char*,
                const char* file,
                unsigned int line,
                const char* message) {
    int level = KLOG_ERROR_LEVEL;
    switch(severity) {
        case android::base::VERBOSE:
            level = KLOG_DEBUG_LEVEL;
            break;
        case android::base::DEBUG:
            level = KLOG_DEBUG_LEVEL;
            break;
        case android::base::INFO:
            level = KLOG_NOTICE_LEVEL;
            break;
        case android::base::WARNING:
            level = KLOG_WARNING_LEVEL;
            break;
        case android::base::ERROR:
            level = KLOG_ERROR_LEVEL;
            break;
        case android::base::FATAL:
            level = KLOG_ERROR_LEVEL;
            break;
    }
    std::string log_message = android::base::StringPrintf("init: %s\n", message);

    iovec iov[1];
    iov[0].iov_base = (void*)log_message.c_str();
    iov[0].iov_len = log_message.size();

    klog_writev(level, iov, 1);
}

void InitLogging(void) {
    klog_init();
    klog_set_level(KLOG_NOTICE_LEVEL);
    SetLogger(KlogLogger);
}