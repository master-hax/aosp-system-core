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

#include <ICastAuth.h>
#include <android-base/unique_fd.h>
#include <assert.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransportTrusty.h>
#include <gtest/gtest.h>
#include <stdint.h>
#include <trusty/tipc.h>

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"

namespace android {

class CastAuthTest : public testing::Test {
  protected:
    void SetUp() override {
        // TODO: make device name configurable
        int srv_fd = tipc_connect(TRUSTY_DEVICE_NAME, ICastAuth::PORT().c_str());
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

        mSrv = ICastAuth::asInterface(root);
        ASSERT_NE(mSrv.get(), nullptr);
    }

    sp<RpcSession> mSess;
    sp<ICastAuth> mSrv;
};

TEST_F(CastAuthTest, ProvisionKey) {
    std::vector<uint8_t> key{uint8_t{255}, uint8_t{0}, uint8_t{127}};
    auto status = mSrv->ProvisionKey(key);
    ASSERT_TRUE(status.isOk());
}

TEST_F(CastAuthTest, SignHash) {
    std::vector<uint8_t> hash{uint8_t{255}, uint8_t{0}, uint8_t{127}};
    std::vector<uint8_t> signature;
    auto status = mSrv->SignHash(hash, &signature);
    ASSERT_TRUE(status.isOk());
}

}  // namespace android
