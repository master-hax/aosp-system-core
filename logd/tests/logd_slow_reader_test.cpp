/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <poll.h>

#include <atomic>
#include <chrono>
#include <thread>

#include <android-base/stringprintf.h>
#include <gtest/gtest.h>
#include <log/log.h>

using android::base::StringPrintf;
using namespace std::literals;

struct ListCloser {
    void operator()(struct logger_list* list) { android_logger_list_close(list); }
};

// Copied from liblog/logger.h
struct logger_list {
    std::atomic<int> fd;
    int mode;
    unsigned int tail;
    log_time start;
    pid_t pid;
    uint32_t log_mask;
};

// Copied from logcat.cpp
static std::pair<unsigned long, const char*> format_of_size(unsigned long value) {
    static const char multipliers[][3] = {{""}, {"Ki"}, {"Mi"}, {"Gi"}};
    size_t i;
    for (i = 0; (i < sizeof(multipliers) / sizeof(multipliers[0])) && (value >= 1024);
         value /= 1024, ++i)
        ;
    return std::make_pair(value, multipliers[i]);
}

TEST(logd, worst_case_reader) {
    const auto kTestTime = 10s;
    const auto kLogId = LOG_ID_MAIN;
    const auto test_start = std::chrono::steady_clock::now();

    std::atomic<bool> test_finished = false;

    auto reporting_thread = std::thread([&] {
        auto logger_list =
                std::unique_ptr<struct logger_list, ListCloser>{android_logger_list_alloc(0, 0, 0)};
        ASSERT_TRUE(logger_list);

        auto logger = android_logger_open(logger_list.get(), kLogId);
        ASSERT_NE(nullptr, logger);

        while (!test_finished) {
            long size = android_logger_get_log_size(logger);
            long readable = android_logger_get_log_readable_size(logger);

            auto size_format = format_of_size(size);
            auto readable_format = format_of_size(readable);

            GTEST_LOG_(INFO) << StringPrintf("ring buffer is %lu %sB (%lu %sB consumed)",
                                             size_format.first, size_format.second,
                                             readable_format.first, readable_format.second);

            // Report log consumption
            std::this_thread::sleep_for(1s);
        }
    });

    auto logging_thread = std::thread([&] {
        size_t ii = 0;
        while (!test_finished) {
            auto message = std::string(3000, 'x');
            message += StringPrintf("%zu", ii++);
            EXPECT_LE(0, __android_log_buf_write(kLogId, ANDROID_LOG_INFO, "logd_test",
                                                 message.c_str()));
            // We want to write a lot, but we don't want to completely saturate logd.
            std::this_thread::sleep_for(200us);
        }
    });

    while (std::chrono::steady_clock::now() < test_start + kTestTime) {
        auto logger_list = std::unique_ptr<struct logger_list, ListCloser>{
                android_logger_list_open(kLogId, ANDROID_LOG_RDONLY, 1000, 0)};
        ASSERT_TRUE(logger_list);

        // Read only entry to set a watermark in logd, but never read again.
        log_msg log_msg;
        auto result = android_logger_list_read(logger_list.get(), &log_msg);
        if (result <= 0) {
            continue;
        }

        // Poll until we get an error, indicating that we've been disconnected.  Then we immediately
        // reconnect, trying to catch logd before it was able to prune.
        struct pollfd poll_fds[] = {
                {
                        .fd = logger_list->fd.load(),
                        .events = 0,
                },
        };
        EXPECT_EQ(1, poll(poll_fds, 1, -1));
        EXPECT_EQ(POLLHUP, poll_fds[0].revents);

        GTEST_LOG_(INFO) << "Reconnecting reader";
    }

    // See if logd recovers once the readers disconnect.
    std::this_thread::sleep_for(2s);

    test_finished = true;

    reporting_thread.join();
    logging_thread.join();
}
