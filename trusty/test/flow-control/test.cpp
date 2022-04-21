/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <string.h>
#include <trusty/tipc.h>

#include "tipc.h"

using ::android::base::unique_fd;

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define MAX_MSG_SIZE \
    (sizeof(struct flow_control_test_srv_hdr) + FLOW_CONTROL_TEST_SRV_FRAG_MAX_SIZE)

namespace android {
namespace trusty {

class FlowControlTest : public ::testing::Test {
  public:
    void SetUp() override {
        srv_.reset(tipc_connect(TIPC_DEV, FLOW_CONTROL_TEST_SRV_PORT));
        ASSERT_GE(srv_, 0);
    }

    void TearDown() override { srv_.reset(); }

    unique_fd srv_;
};

TEST_F(FlowControlTest, AtMsgQueueLimit) {
    uint8_t msg[MAX_MSG_SIZE];
    int rc = write(srv_, msg, sizeof(msg));
    ASSERT_EQ(rc, MAX_MSG_SIZE) << strerror(errno);
}

TEST_F(FlowControlTest, LargerThanSrvMsgQueueLimit) {
    uint8_t msg[MAX_MSG_SIZE + 1];
    int rc = write(srv_, msg, sizeof(msg));
    ASSERT_LT(rc, 0) << strerror(errno);
}

TEST_F(FlowControlTest, LargerThanTIPCMsgQueue) {
    uint8_t msg[PAGE_SIZE * 2];
    int rc = write(srv_, msg, sizeof(msg));
    ASSERT_LT(rc, 0) << strerror(errno);
}

TEST_F(FlowControlTest, EchoOneFrag) {
    uint8_t msg[FLOW_CONTROL_TEST_SRV_FRAG_MAX_SIZE];

    flow_control_test_srv_hdr hdr = {
            .cmd = FLOW_CONTROL_TEST_SRV_MSG | FLOW_CONTROL_TEST_SRV_STOP_BIT,
            .frag_len = sizeof(msg),
    };

    struct iovec iovs[] = {
            {
                    .iov_base = &hdr,
                    .iov_len = sizeof(hdr),
            },
            {
                    .iov_base = msg,
                    .iov_len = sizeof(msg),
            },
    };

    int rc = writev(srv_, iovs, 2);
    ASSERT_EQ(rc, sizeof(hdr) + sizeof(msg));
}

}  // namespace trusty
}  // namespace android
