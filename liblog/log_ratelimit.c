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
#include <pthread.h>
#include <time.h>

#include <log/log.h>

#include "log_portability.h"

static time_t last_clock;
static time_t last_seconds;
static pthread_mutex_t lock_ratelimit = PTHREAD_MUTEX_INITIALIZER;

/*
 * if last is NULL, caller _must_ provide a consistent value for
 * seconds, otherwise we will take the maximum ever issued and hold
 * on to that.  Preserves value of errno, except if it is zero.
 * Return -1 if we can not acquire a lock (for example. inside a
 * signal handler), 0 if we are not to log a message, and 1 if we
 * are ok to log a message.
 */
LIBLOG_ABI_PUBLIC int __android_log_ratelimit(time_t seconds, time_t* last)
{
    time_t now;
    int save_errno = errno;

    if (pthread_mutex_trylock(&lock_ratelimit)) {
        if (save_errno) {
            errno = save_errno;
        }
        return -1;
    }

    time(&now);

    if (seconds == 0) {
        seconds = 10; /* default policy */
    } else if (seconds <= 1) {
        seconds = 2;  /* granularity */
    } else if (seconds > (24 * 60 * 60)) {
        seconds = 24 * 60 * 60; /* maximum of a day */
    }

    if (!last) {
        if (last_seconds > seconds) {
            seconds = last_seconds;
        } else if (last_seconds < seconds) {
            last_seconds = seconds;
        }
        last = &last_clock; /* global clock */
    }

    if ((*last + seconds) > now) {
        pthread_mutex_unlock(&lock_ratelimit);
        if (save_errno) {
            errno = save_errno;
        }
        return 0;
    }
    *last = now;
    pthread_mutex_unlock(&lock_ratelimit);
    if (save_errno) {
        errno = save_errno;
    }
    return 1;
}
