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

#include <experimental/string_view>

#include <log/uio.h>

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
