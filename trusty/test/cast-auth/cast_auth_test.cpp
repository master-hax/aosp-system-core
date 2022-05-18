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

#include <BpCastAuth.h>
#include <assert.h>

#include <gtest/gtest.h>
#include <stdint.h>
#include <trusty/tipc.h>

namespace android {

class CastAuthTest : public testing::Test {
protected:
    void SetUp() override {
    int ret;
        ret = aidl::BpCastAuth::connect(mSrv, aidl::ICastAuth::PORT, 0);
        ASSERT_EQ(ret, android::OK);
    }
    std::optional<aidl::BpCastAuth> mSrv;
};

TEST_F(CastAuthTest, ProvisionKey) {
    std::vector<uint8_t> key{uint8_t{255}, uint8_t{0}, uint8_t{127}};
    const trusty::aidl::Payload pkey{const_cast<uint8_t*>(key.data()),
                                    static_cast<uint32_t>(key.size())};
    auto status = mSrv->ProvisionKey(pkey);
    ASSERT_TRUE(status == android::OK);
}

TEST_F(CastAuthTest, SignHash) {
    std::vector<uint8_t> hash{uint8_t{255}, uint8_t{0}, uint8_t{127}};
    std::vector<uint8_t> signature;
    const trusty::aidl::Payload phash{const_cast<uint8_t*>(hash.data()),
                                    static_cast<uint32_t>(hash.size())};
    trusty::aidl::Payload psignature{
            signature.data(), static_cast<uint32_t>(signature.size())};
    auto status = mSrv->SignHash(phash, &psignature);
    ASSERT_TRUE(status == android::OK);
}

}  // namespace android
