/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <trusty/metrics/metrics.h>
#include <trusty/tipc.h>
#include <iostream>

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define CRASHER_PORT "com.android.trusty.crashtest.crasher"

namespace android {
namespace trusty {
namespace metrics {

using android::base::unique_fd;

enum crasher_command {
    CRASHER_NOP,
    CRASHER_EXIT_SUCCESS,
    CRASHER_EXIT_FAILURE,
    CRASHER_READ_NULL_PTR,
    CRASHER_READ_BAD_PTR,
    CRASHER_WRITE_BAD_PTR,
    CRASHER_WRITE_RO_PTR,
    CRASHER_EXEC_RODATA,
    CRASHER_EXEC_DATA,
};

struct crasher_msg {
    uint8_t cmd;
};

TEST(MetricsTest, Crash) {
    std::string crashed_app;

    auto metrics = TrustyMetrics::CreateTrustyMetrics(
            TIPC_DEV, [&crashed_app](std::string app_id) { crashed_app = app_id; });
    ASSERT_NE(metrics, nullptr);

    unique_fd crasher(tipc_connect(TIPC_DEV, CRASHER_PORT));
    ASSERT_GE(crasher, 0);

    crasher_msg msg = {.cmd = CRASHER_READ_NULL_PTR};
    int rc = write(crasher, &msg, sizeof(msg));
    ASSERT_EQ(rc, sizeof(msg));

    auto ret = metrics->HandleOneEvent(5 /* timeout_sec */);
    ASSERT_TRUE(ret.ok());
    // Check that it's crasher app that crashed.
    ASSERT_EQ(crashed_app, "7ee4dddc-177a-420a-96ea-5d413d88228e");
}

}  // namespace metrics
}  // namespace trusty
}  // namespace android
