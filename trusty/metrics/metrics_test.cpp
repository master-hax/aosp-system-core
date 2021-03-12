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
#define CRASHER_PORT "com.android.trusty.metrics.test.crasher"

namespace android {
namespace trusty {
namespace metrics {

using android::base::unique_fd;

static void TriggerCrash() {
    unique_fd crasher(tipc_connect(TIPC_DEV, CRASHER_PORT));
    ASSERT_GE(crasher, 0);

    int msg = 0;
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
    TriggerCrash();
    WaitForEvent();

    /* Check that correct TA crashed. */
    ASSERT_EQ(crashed_app_, "36f5b435-5bd3-4526-8b76-200e3a7e79f3:crasher");
    crashed_app_.clear();
}

TEST_F(TrustyMetricsTest, EventDrop) {
    /* We know the size of the internal event queue is less than this. */
    size_t num_events = 3;

    ASSERT_EQ(event_drop_count_, 0);

    for (auto i = 0; i < num_events; i++) {
        TriggerCrash();
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
