/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef __TRACE_DEV_INC
#define __TRACE_DEV_INC

#define LOG_TAG "cutils-trace"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <cutils/compiler.h>
#include <cutils/properties.h>
#include <cutils/trace.h>
#include <log/log.h>
#include <log/log_properties.h>

/**
 * Maximum size of a message that can be logged to the trace buffer.
 * Note this message includes a tag, the pid, and the string given as the name.
 * Names should be kept short to get the most use of the trace buffer.
 */
#define ATRACE_MESSAGE_LENGTH 1024

atomic_bool             atrace_is_ready      = ATOMIC_VAR_INIT(false);
int                     atrace_marker_fd     = -1;
_Atomic(uint64_t)       atrace_enabled_tags  = ATOMIC_VAR_INIT(ATRACE_TAG_NOT_READY);
_Atomic(uint32_t)       last_sequence_number = ATOMIC_VAR_INIT(4294967295);
static bool             atrace_is_debuggable = ATOMIC_VAR_INIT(false);
static atomic_bool      atrace_is_enabled    = ATOMIC_VAR_INIT(true);
alignas(4096) AtraceShmemPage atrace_shmem   = {};

// Set whether this process is debuggable, which determines whether
// application-level tracing is allowed when the ro.debuggable system property
// is not set to '1'.
void atrace_set_debuggable(bool debuggable)
{
    atrace_is_debuggable = debuggable;
    atrace_update_tags();
}

// Check whether the given command line matches one of the comma-separated
// values listed in the app_cmdlines property.
static bool atrace_is_cmdline_match(const char* cmdline)
{
    ptrdiff_t len = strlen(cmdline);

    char* enabled_cmdlines = atrace_shmem.enabled_cmdlines;
    const char* enabled_cmdlines_end = enabled_cmdlines + sizeof(atrace_shmem.enabled_cmdlines);

    while (enabled_cmdlines < enabled_cmdlines_end) {
        char* end = (char*)memchr(enabled_cmdlines, '\0', enabled_cmdlines_end - enabled_cmdlines);
        if (end == NULL) {
            return false;
        }
        if (end == enabled_cmdlines) {
            return false;
        }
        if (end - enabled_cmdlines == 1 && *enabled_cmdlines == '*') {
            return true;
        }
        if (end - enabled_cmdlines == len && strncmp(enabled_cmdlines, cmdline, len) == 0)  {
            return true;
        }
        enabled_cmdlines = end + 1;
    }
    return false;
}

// Determine whether application-level tracing is enabled for this process.
static bool atrace_is_app_tracing_enabled()
{
    bool sys_debuggable = property_get_bool("ro.debuggable", 0);
    bool result = false;

    if (sys_debuggable || atrace_is_debuggable) {
        // Check whether tracing is enabled for this process.
        FILE * file = fopen("/proc/self/cmdline", "re");
        if (file) {
            char cmdline[4096];
            if (fgets(cmdline, sizeof(cmdline), file)) {
                result = atrace_is_cmdline_match(cmdline);
            } else {
                ALOGE("Error reading cmdline: %s (%d)", strerror(errno), errno);
            }
            fclose(file);
        } else {
            ALOGE("Error opening /proc/self/cmdline: %s (%d)", strerror(errno),
                    errno);
        }
    }

    return result;
}

// Read the sysprop and return the value tags should be set to
static uint64_t atrace_get_property()
{
    uint64_t tags = atrace_shmem.atrace_requested_tags;

    // Only set the "app" tag if this process was selected for app-level debug
    // tracing.
    if (atrace_is_app_tracing_enabled()) {
        tags |= ATRACE_TAG_APP;
    } else {
        tags &= ~ATRACE_TAG_APP;
    }

    return (tags | ATRACE_TAG_ALWAYS) & ATRACE_TAG_VALID_MASK;
}

// Update tags if tracing is ready. Useful as a sysprop change callback.
void atrace_update_tags()
{
    uint64_t tags;
    if (CC_UNLIKELY(atomic_load_explicit(&atrace_is_ready, memory_order_acquire))) {
        if (atomic_load_explicit(&atrace_is_enabled, memory_order_acquire)) {
            tags = atrace_get_property();
            atomic_store_explicit(&atrace_enabled_tags, tags, memory_order_relaxed);
        } else {
            // Tracing is disabled for this process, so we simply don't
            // initialize the tags.
            atomic_store_explicit(&atrace_enabled_tags, static_cast<uint64_t>(ATRACE_TAG_NOT_READY), memory_order_relaxed);
        }
    }
}

#define WRITE_MSG(format_begin, format_end, name, value) { \
    char buf[ATRACE_MESSAGE_LENGTH]; \
    int pid = getpid(); \
    int len = snprintf(buf, sizeof(buf), format_begin "%s" format_end, pid, \
        name, value); \
    if (len >= (int) sizeof(buf)) { \
        /* Given the sizeof(buf), and all of the current format buffers, \
         * it is impossible for name_len to be < 0 if len >= sizeof(buf). */ \
        int name_len = strlen(name) - (len - sizeof(buf)) - 1; \
        /* Truncate the name to make the message fit. */ \
        ALOGW("Truncated name in %s: %s\n", __FUNCTION__, name); \
        len = snprintf(buf, sizeof(buf), format_begin "%.*s" format_end, pid, \
            name_len, name, value); \
    } \
    write(atrace_marker_fd, buf, len); \
}

#endif  // __TRACE_DEV_INC
