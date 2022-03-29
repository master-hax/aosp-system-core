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

#include <ITestService.h>
#include <android-base/unique_fd.h>
#include <assert.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransportTrusty.h>
#include <gtest/gtest.h>
#include <stdint.h>
#include <trusty/tipc.h>

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"

namespace android {

class BinderTest : public testing::Test {
  protected:
    void SetUp() override {
        // TODO: make device name configurable
        int srv_fd = tipc_connect(TRUSTY_DEVICE_NAME, ITestService::PORT().c_str());
        ASSERT_GE(srv_fd, 0);

        mSess = RpcSession::make(RpcTransportCtxFactoryTrusty::make());
        mSess->setMaxIncomingThreads(0);
        mSess->setMaxOutgoingThreads(1);

        base::unique_fd srv_ufd(srv_fd);
        auto status = mSess->setupPreconnectedClient(std::move(srv_ufd),
                                                     []() { return base::unique_fd(); });
        ASSERT_EQ(status, OK);

        auto root = mSess->getRootObject();
        ASSERT_NE(root.get(), nullptr);

        mSrv = ITestService::asInterface(root);
        ASSERT_NE(mSrv.get(), nullptr);
    }

    sp<RpcSession> mSess;
    sp<ITestService> mSrv;
};

TEST_F(BinderTest, Add) {
    int32_t result;
    auto status = mSrv->add(2, 3, &result);
    ASSERT_TRUE(status.isOk());
    ASSERT_EQ(result, 5);
}

}  // namespace android
