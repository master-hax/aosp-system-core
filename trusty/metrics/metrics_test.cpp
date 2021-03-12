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

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define CRASHER_PORT "com.android.trusty.crashtest.crasher"

namespace android {
namespace trusty {
namespace metrics {

using android::base::unique_fd;

enum crasher_cmd {
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

static void SendCrasherMsg(enum crasher_cmd cmd) {
    unique_fd crasher(tipc_connect(TIPC_DEV, CRASHER_PORT));
    ASSERT_GE(crasher, 0);

    crasher_msg msg = {.cmd = static_cast<uint8_t>(cmd)};
    int rc = write(crasher, &msg, sizeof(msg));
    ASSERT_EQ(rc, sizeof(msg));
}

class TrustyMetricsTest : public ::testing::Test {
  public:
    virtual void SetUp() override {
        metrics_ = TrustyMetrics::CreateTrustyMetrics(
                TIPC_DEV, [&](std::string app_id) { crashed_app_ = app_id; },
                [&]() { event_drop_count_++; });
        ASSERT_NE(metrics_, nullptr);
    }

    void WaitForEvent() {
        alarm(30 /* seconds */);
        auto ret = metrics_->HandleEvent();
        alarm(0);

        ASSERT_TRUE(ret.ok()) << ret.error();
    }

    std::unique_ptr<TrustyMetrics> metrics_;
    std::string crashed_app_;
    size_t event_drop_count_;
};

TEST_F(TrustyMetricsTest, Crash) {
    SendCrasherMsg(CRASHER_READ_NULL_PTR);
    WaitForEvent();

    /* Check that it's crasher app that crashed. */
    ASSERT_EQ(crashed_app_, "7ee4dddc-177a-420a-96ea-5d413d88228e");
    crashed_app_.clear();
}

TEST_F(TrustyMetricsTest, EventDrop) {
    /* We know the size of the internal event queue is less than this. */
    size_t num_events = 10;

    ASSERT_EQ(event_drop_count_, 0);

    for (auto i = 0; i < num_events; i++) {
        SendCrasherMsg(CRASHER_EXIT_SUCCESS);
    }

    for (auto i = 0; i < num_events; i++) {
        WaitForEvent();
        if (event_drop_count_ > 0) {
            break;
        }
    }

    ASSERT_EQ(event_drop_count_, 1);
}

}  // namespace metrics
}  // namespace trusty
}  // namespace android
