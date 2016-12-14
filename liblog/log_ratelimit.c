/*
** Copyright 2016, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <errno.h>
#include <stdatomic.h>
#include <time.h>

#include <log/log.h>

#include "log_portability.h"

static atomic_uint_fast64_t last_clock;
static atomic_uint_fast64_t last_seconds;

/*
 * if last is NULL, caller _must_ provide a consistent value for
 * seconds, otherwise we will take the maximum ever issued and hold
 * on to that.  Preserves value of errno.  There is a possible race
 * condition which may result in two message being printed in
 * different threads.  We do not care.
 */
LIBLOG_ABI_PUBLIC int __android_log_ratelimit(time_t seconds,
                                              atomic_uint_fast64_t* last)
{
    int save_errno = errno; /* paranoid cult */
    uint64_t now = time(NULL);
    errno = save_errno;

    if (seconds == 0) {
        seconds = 10; /* default policy */
    } else if (seconds <= 1) {
        seconds = 2;  /* granularity */
    } else if (seconds > (24 * 60 * 60)) {
        seconds = 24 * 60 * 60; /* maximum of a day */
    }

    if (!last) {
        time_t current = atomic_load(&last_seconds);
        if (current > seconds) {
            seconds = current;
        } else if (current < seconds) {
            atomic_store(&last_seconds, seconds);
        }
        last = &last_clock; /* global clock */
    }

    if ((atomic_load(last) + seconds) > now) {
        return 0;
    }
    atomic_store(last, now);
    return 1;
}
