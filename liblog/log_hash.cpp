/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "log_hash.h"

#include <pthread.h>
#include <time.h>

#include <experimental/string_view>
#include <list>

#include <log/uio.h>
#include <private/android_logger.h>

#include "log_portability.h"

LIBLOG_HIDDEN size_t __android_log_hash(struct iovec* vecs, int count) {
    size_t total = 0;

    for ( ; count > 0; count--, vecs++) {
        char* msg = static_cast<char*>(vecs->iov_base);
        if (!msg) continue;
        size_t len = vecs->iov_len;
        if (!len) continue;

        total ^= std::hash<std::experimental::string_view>()(
                           std::experimental::string_view(msg, len));
    }
    return total;
}

// Return -1 if we have a trylock failure, 0 if the history of the
// timestamps is below the maximum allowed number of incidents over
// the period, and 1 if the rate is above the number of incidents
// over the period.
LIBLOG_HIDDEN int __android_log_timestamp_ratelimit(struct timespec* ts,
                                                    size_t incidents,
                                                    time_t period) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static std::list<log_time> times;

    log_time t(*ts);

    if (period == 0) {
        if (pthread_mutex_trylock(&lock)) return -1;

        times.clear();
        times.emplace_back(t);

        pthread_mutex_unlock(&lock);
        return 0;
    }

    log_time oldest(t - log_time(period, 0));

    if (pthread_mutex_trylock(&lock)) return -1;

    for (std::list<log_time>::const_iterator it = times.begin(); it != times.end(); ) {
        if ((*it) < oldest) {
            it = times.erase(it);
        } else {
            ++it;
        }
    }
    // Crude assumption that the oldest entries are first, limit the
    // size of the list to maximum number of incidents to scale the
    // algorithm.  If we let the list grow to the actual number of
    // incidents this operation can exceed the savings of merely
    // dropping the excess content.
    while (times.size() > incidents) {
        times.erase(times.begin());
    }
    times.emplace_back(t);
    size_t ret = times.size();

    pthread_mutex_unlock(&lock);
    return ret > incidents;
}
