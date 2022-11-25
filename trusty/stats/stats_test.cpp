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
#include <errno.h>
#include <getopt.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <android-base/expected.h>
#include <android-base/logging.h>
#include <android/frameworks/stats/BnStats.h>
#include <android/frameworks/stats/IStats.h>
#include <android/frameworks/stats/trusty/IStatsSetter.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransportRaw.h>
#include <binder/RpcTransportTipcAndroid.h>
#include <binder/RpcTrusty.h>
#include <trusty/tipc.h>
#include <utils/Condition.h>
#include <utils/Mutex.h>
#include <utils/Vector.h>

/** DOC:
 * ./build-root/build-qemu-generic-arm64-test-debug/run \
 *       --android $HOME/depot/android/aosp \
 *       --headless --shell-command "/data/nativetest64/vendor/trusty_stats_test/trusty_stats_test"
 * adb -s emulator-5554 shell /data/nativetest64/vendor/trusty_stats_test/trusty_stats_test
 */
using namespace android;
using android::base::unique_fd;
using ::binder::Status;
using ::frameworks::stats::BnStats;
using ::frameworks::stats::IStats;
using ::frameworks::stats::VendorAtom;
using ::frameworks::stats::VendorAtomValue;
using ::frameworks::stats::trusty::IStatsSetter;

constexpr const char kTrustyDefaultDeviceName[] = "/dev/trusty-ipc-dev0";
constexpr const char kTrustyStatsPortTest[] = "com.android.trusty.stats.test";

enum TrustyAtoms { TrustyAppCrashed = 100072, TrustyError = 100140, TrustyStorageError = 100141 };

enum TestMsgHeader {
    TEST_PASSED = 0,
    TEST_FAILED = 1,
    TEST_MESSAGE = 2,
};

namespace android {
namespace trusty {
namespace stats {

class Stats : public BnStats {
  public:
    Stats() : BnStats() {}
    Status reportVendorAtom(const ::VendorAtom& vendorAtom) {
        ALOGD("reportVendorAtom atomId = %d\n", vendorAtom.atomId);
        Mutex::Autolock autolock(mLock);
        mQueueVendorAtom.push_front(std::move(vendorAtom));
        mCondVar.signal();
        return Status::ok();
    }

    status_t getVendorAtom(VendorAtom* pVendorAtom, int64_t waitUntilNs) {
        Mutex::Autolock lock(mLock);
        while (mQueueVendorAtom.isEmpty()) {
            auto rc = mCondVar.waitRelative(mLock, waitUntilNs);
            if (rc != NO_ERROR) {
                return rc;
            }
        }
        *pVendorAtom = std::move(mQueueVendorAtom.top());
        mQueueVendorAtom.pop();
        return NO_ERROR;
    }

  private:
    Mutex mLock;
    Condition mCondVar;
    Vector<VendorAtom> mQueueVendorAtom;
};

class TrustyStatsTest : public ::testing::Test {
  protected:
    TrustyStatsTest() : mPortTestFd(-1){};
    void SetUp() override {
        // Commenting out the server portion because we do not have any direct incoming call
        // Calls from TA are currently being handle on the extra thread on the session.
        // android::sp<::android::RpcServer> server =
        // ::android::RpcServer::make(::android::RpcTransportCtxFactoryRaw::make());

        mStats = android::sp<Stats>::make();
        // Increasing number of incoming threads on session to be able to receive callbacks
        std::function<void(sp<RpcSession>&)> session_initializer = [](auto session) {
            session->setMaxIncomingThreads(1);
        };

        auto session = RpcTrustyConnectWithSessionInitializer(
                kTrustyDefaultDeviceName, IStatsSetter::PORT().c_str(), session_initializer);
        ASSERT_EQ(session != nullptr, true);
        auto root = session->getRootObject();
        ASSERT_EQ(root != nullptr, true);
        auto statsSetter = IStatsSetter::asInterface(root);
        ASSERT_EQ(statsSetter != nullptr, true);

        statsSetter->setInterface(mStats);
    }
    void TearDown() override {
        /* close connection to unitest app */
        if (mPortTestFd != -1) {
            tipc_close(mPortTestFd);
        }
        mPortTestFd = -1;
        mStats.clear();
    }
    void StartPortTest() {
        /* connect to unitest app */
        mPortTestFd = tipc_connect(kTrustyDefaultDeviceName, kTrustyStatsPortTest);
        if (mPortTestFd < 0) {
            ALOGE("failed to connect to '%s' app: %s\n", kTrustyStatsPortTest,
                  strerror(-mPortTestFd));
        }
        ASSERT_GT(mPortTestFd, 0);
    }
    void WaitPortTestDone() {
        /* wait for test to complete */
        char rxBuf[1024];
        ASSERT_NE(mPortTestFd, -1);
        for (;;) {
            int rc = read(mPortTestFd, rxBuf, sizeof(rxBuf));
            ASSERT_GT(rc, 0);
            ASSERT_LT(rc, (int)sizeof(rxBuf));
            if (rxBuf[0] == TEST_PASSED) {
                break;
            } else if (rxBuf[0] == TEST_FAILED) {
                break;
            } else if (rxBuf[0] == TEST_MESSAGE) {
                write(STDOUT_FILENO, "Trusty PORT_TEST: ", 18);
                write(STDOUT_FILENO, rxBuf + 1, rc - 1);
            } else {
                ALOGE("Bad message header: %d\n", rxBuf[0]);
                break;
            }
        }
        ASSERT_EQ(rxBuf[0], TEST_PASSED);
    }
    android::sp<Stats> mStats;
    int mPortTestFd;
};

#define blockUntilMs 500
TEST_F(TrustyStatsTest, CheckAtoms) {
    VendorAtom vendorAtom;
    int expectedAtomCnt = 2;
    StartPortTest();
    while (--expectedAtomCnt) {
        EXPECT_EQ(NO_ERROR, mStats->getVendorAtom(&vendorAtom, blockUntilMs * 1000000));
        EXPECT_THAT(vendorAtom.atomId,
                    ::testing::AnyOf(::testing::Eq(TrustyAtoms::TrustyAppCrashed),
                                     ::testing::Eq(TrustyAtoms::TrustyError),
                                     ::testing::Eq(TrustyAtoms::TrustyStorageError)));
        EXPECT_STREQ(String8(vendorAtom.reverseDomainName), "google.android.trusty");
        if (vendorAtom.atomId == TrustyAtoms::TrustyAppCrashed) {
            EXPECT_STREQ(String8(vendorAtom.values[0].get<VendorAtomValue::stringValue>()),
                         "5247d19b-cf09-4272-a450-3ef20dbefc14");
            ALOGD("%d, %s, %s\n", vendorAtom.atomId, String8(vendorAtom.reverseDomainName).c_str(),
                  String8(vendorAtom.values[0].get<VendorAtomValue::stringValue>()).c_str());
        }
        ALOGD("%d, %s\n", vendorAtom.atomId, String8(vendorAtom.reverseDomainName).c_str());
    };
    WaitPortTestDone();
};

}  // namespace stats
}  // namespace trusty
}  // namespace android
