/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include <log/logcat.h>

using namespace std::chrono;

namespace {

static std::string& appendError(std::string& content, const char* msg) {
    // helper bonus: newline only if we need it ...
    if ((content.size() > 0) && (content[content.size() - 1] != '\n')) {
        content += '\n';
    }
    // Boilerplate error report
    content += "Error: ";
    content += msg;
    return content;
}

}  // namespace

std::string android::ExecuteLogcatCommand(const std::string& command,
                                          size_t max_size,
                                          milliseconds relative_timeout) {
    static constexpr size_t maximum_reserve_size = 256 * BUFSIZ;
    android_logcat_context ctx;
    auto fp = android_logcat_popen(&ctx, command.c_str());
    if (fp == nullptr) return "Error: popen";

    bool skip_poll = relative_timeout == milliseconds::max();

    auto fd = fileno(fp);
    struct pollfd pfd = {.fd = fd, .events = POLLIN };

    auto start = steady_clock::now();

    if (max_size > SSIZE_MAX) {
        max_size = SSIZE_MAX;
    }
    std::string content;
    if (max_size < maximum_reserve_size) {
        content.reserve(max_size);
    }

    for (;;) {
        static constexpr milliseconds zero(0);
        milliseconds remaining_timeout;

        if (!skip_poll) {
            auto diff = steady_clock::now() - start;
            auto time_elapsed = duration_cast<milliseconds>(diff);
            remaining_timeout = relative_timeout - time_elapsed;

            auto rc = poll(&pfd, 1, std::max(remaining_timeout, zero).count());
            if (rc == -1) {
                if (errno == EINTR) continue;
                appendError(content, "poll ") += strerror(errno);
            }
            if (rc <= 0) break;
        }

        ssize_t remaining_file_size = max_size - content.size();
        if (remaining_file_size <= 0) {
            appendError(content, "size");
            break;
        }

        char buf[BUFSIZ];
        auto n = TEMP_FAILURE_RETRY(read(
            fd, &buf[0],
            std::min(static_cast<size_t>(remaining_file_size), sizeof(buf))));
        if (n == -1) appendError(content, "read ") += strerror(errno);
        if (n <= 0) break;
        content.append(buf, n);

        if (content.size() >= max_size) {
            appendError(content, "size");
            break;
        }
    }
    auto retval = android_logcat_pclose(&ctx, fp);
    if (retval) appendError(content, "exit code ") += std::to_string(retval);
    return content;
}
