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

#ifndef _LIBLOG_LOG_HASH_H__
#define _LIBLOG_LOG_HASH_H__

#include <time.h>

#include <log/uio.h>

#include "log_portability.h"

__BEGIN_DECLS

LIBLOG_HIDDEN size_t __android_log_hash(struct iovec* vecs, int count);

LIBLOG_HIDDEN int __android_log_timestamp_ratelimit(struct timespec* ts,
                                                    size_t incidents,
                                                    time_t period);
__END_DECLS

#endif /* _LIBLOG_LOG_HASH_H__ */
