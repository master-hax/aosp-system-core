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
#include <android-base/result.h>
#include <android-base/unique_fd.h>
// #include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trusty/busy_test/busy_test.h>
#include <trusty/tipc.h>
#include <utils/Log.h>

using android::base::ErrnoError;
using android::base::Error;

#define SMP_MAX_CPUS 8

/* trusty thread priorities */
#define NUM_PRIORITIES 32
#define LOWEST_PRIORITY 0
#define HIGHEST_PRIORITY (NUM_PRIORITIES - 1)
#define DPC_PRIORITY (NUM_PRIORITIES - 2)
#define IDLE_PRIORITY LOWEST_PRIORITY
#define LOW_PRIORITY (NUM_PRIORITIES / 4)
#define DEFAULT_PRIORITY (NUM_PRIORITIES / 2)
#define HIGH_PRIORITY ((NUM_PRIORITIES / 4) * 3)

using android::base::Result;
using android::base::unique_fd;

/** DOC:
 * ./build-root/build-qemu-generic-arm64-test-debug/run \
 *       --android $HOME/depot/android/aosp \
 *       --headless --shell-command "/data/nativetest64/vendor/trusty_qos_test/trusty_qos_test"
 * adb -s emulator-5554 shell /data/nativetest64/vendor/trusty_qos_test/trusty_qos_test
 */
constexpr const char kTrustyDefaultDeviceName[] = "/dev/trusty-ipc-dev0";
constexpr const char kTrustyBusyPortTest[] = "com.android.kernel.busy-test";

namespace android {
namespace trusty {
namespace qos {
class TrustyQosTest : public ::testing::Test {
  protected:
    TrustyQosTest() : mPortTestFd(-1) {}
    void SetUp() override {
        auto ret = OpenBusyTest();
        ASSERT_TRUE(ret.ok()) << ret.error();
    }
    void TearDown() override {
        // note: mPortTestFd unique_fd will close on TrustyQosTest dtor
    }
    void SetPriority(uint32_t cpu, uint32_t priority) {
        struct {
            struct busy_test_req hdr;
            struct busy_test_set_priority_req set_priority;
        } req = {
                .hdr.cmd = BUSY_TEST_CMD_SET_PRIORITY,
                .hdr.reserved = 0,
                .set_priority.cpu = cpu,
                .set_priority.priority = priority,
        };

        auto rc = write(mPortTestFd, &req, sizeof(req));
        ASSERT_EQ(rc, (int)sizeof(req));
        struct busy_test_resp resp = {};

        rc = read(mPortTestFd, &resp, sizeof(resp));
        ASSERT_EQ(rc, (int)sizeof(resp));
        ASSERT_EQ(resp.cmd, req.hdr.cmd | BUSY_TEST_CMD_RESP_BIT);
        ASSERT_EQ(resp.status, BUSY_TEST_NO_ERROR);
    }
    Result<void> OpenBusyTest() {
        int fd = tipc_connect(kTrustyDefaultDeviceName, kTrustyBusyPortTest);
        if (fd < 0) {
            return ErrnoError() << "failed to connect to Trusty metrics TA";
        }

        mPortTestFd.reset(fd);
        return {};
    }
    unique_fd mPortTestFd;
};

TEST_F(TrustyQosTest, SetPriorityHighPlus) {
    SetPriority(0, HIGH_PRIORITY);
    sleep(360);
};
}  // namespace qos
}  // namespace trusty
}  // namespace android
