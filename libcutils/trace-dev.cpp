/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <sys/mman.h>

#include <cutils/trace.h>

#include "trace-dev.inc"

static pthread_once_t atrace_once_control = PTHREAD_ONCE_INIT;

// Set whether tracing is enabled in this process.  This is used to prevent
// the Zygote process from tracing.
void atrace_set_tracing_enabled(bool enabled)
{
    atomic_store_explicit(&atrace_is_enabled, enabled, memory_order_release);
    atrace_update_tags();
}

static void atrace_init_once()
{
    atrace_marker_fd = open("/sys/kernel/debug/tracing/trace_marker", O_WRONLY | O_CLOEXEC);
    if (atrace_marker_fd == -1) {
        ALOGE("Error opening trace file: %s (%d)", strerror(errno), errno);
        atrace_enabled_tags = 0;
    } else {
      atrace_enabled_tags = atrace_get_property();
    }
}

static void atrace_setup_shmem() {
    int fd = open("/dev/__atrace_shmem__", O_RDONLY);
    if (fd != -1) {
        if (mmap(&atrace_shmem, sizeof(AtraceShmemPage),
              PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) == MAP_FAILED) {
            ALOGE("Error remapping atrace_shmem: %d.", errno);
        }
        close(fd);
    } else {
        ALOGE("Error opening /dev/__atrace_shmem__.");
    }
    pthread_once(&atrace_once_control, atrace_init_once);
}

void atrace_seq_number_changed(uint32_t prev_seq_no, uint32_t seq_no) {
    // Someone raced us.
    if (!atomic_compare_exchange_strong(&last_sequence_number, &prev_seq_no, seq_no)) {
        return;
    }
    if (CC_UNLIKELY(seq_no == 0)) {
        ALOGI("atrace_setup_shmem");
        atrace_setup_shmem();
    }
    atomic_load_explicit(&atrace_shmem.atrace_sequence_number, memory_order_acquire);
    atrace_update_tags();
}

// This is only called by programs inlining old versions of the header.
// This gets called on every atrace event because we permanentely set
// atrace_is_ready to false, which causes this being called.
void atrace_setup()
{
    atrace_init();
}

void atrace_begin_body(const char* name)
{
    WRITE_MSG("B|%d|", "%s", name, "");
}

void atrace_end_body()
{
    WRITE_MSG("E|%d", "%s", "", "");
}

void atrace_async_begin_body(const char* name, int32_t cookie)
{
    WRITE_MSG("S|%d|", "|%" PRId32, name, cookie);
}

void atrace_async_end_body(const char* name, int32_t cookie)
{
    WRITE_MSG("F|%d|", "|%" PRId32, name, cookie);
}

void atrace_int_body(const char* name, int32_t value)
{
    WRITE_MSG("C|%d|", "|%" PRId32, name, value);
}

void atrace_int64_body(const char* name, int64_t value)
{
    WRITE_MSG("C|%d|", "|%" PRId64, name, value);
}
