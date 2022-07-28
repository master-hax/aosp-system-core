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

#include <BnTestService.h>
#include <ITestService.h>
#include <android-base/unique_fd.h>
#include <assert.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransportTipcAndroid.h>
#include <gtest/gtest.h>
#include <stdint.h>
#include <trusty/tipc.h>

namespace android {

constexpr const char kTrustyDefaultDeviceName[] = "/dev/trusty-ipc-dev0";


using android::String16;
using android::binder::Status;

template <typename T>
Status ReverseArray(const std::vector<T>& input,
                    std::vector<T>* repeated,
                    std::vector<T>* _aidl_return) {
    *repeated = input;
    *_aidl_return = input;
    std::reverse(_aidl_return->begin(), _aidl_return->end());
    return Status::ok();
}
class BinderTest : public testing::Test {
  protected:
    void SetUp() override {
        mSess = RpcSession::make(RpcTransportCtxFactoryTipcAndroid::make());
        auto status = mSess->setupPreconnectedClient({}, []() {
            // TODO: make device name configurable
            return base::unique_fd(
                    tipc_connect(kTrustyDefaultDeviceName, ITestService::PORT().c_str()));
        });
        ASSERT_EQ(status, OK);

        auto root = mSess->getRootObject();
        ASSERT_NE(root.get(), nullptr);

        mSrv = ITestService::asInterface(root);
        ASSERT_NE(mSrv.get(), nullptr);
    }

    template <typename T, typename U, typename V>
    void CheckRepeat(Status (ITestService::*func)(T, U*), V in) {
        U out;
        auto status = (mSrv.get()->*func)(in, &out);
        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(in, out);
    }

    void CheckRepeat(const String16& in) {
        String16 out;
        auto status = mSrv->RepeatString(in, &out);
        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(in, out);
    }

    template <typename T>
    void CheckReverse(Status (ITestService::*func)(const std::vector<T>&, std::vector<T>*,
                                                   std::vector<T>*),
                      const std::vector<T>& input) {
        // must be preallocated for Java servers
        std::vector<T> repeated(input.size());
        std::vector<T> reversed(input.size());
        auto status = (mSrv.get()->*func)(input, &repeated, &reversed);
        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(repeated, input);

        std::vector<T> reversed_input(input);
        std::reverse(reversed_input.begin(), reversed_input.end());
        EXPECT_EQ(reversed, reversed_input);
    }

    sp<RpcSession> mSess;
    sp<ITestService> mSrv;
};

#define CHECK_REPEAT(func, in) \
    { CheckRepeat(&ITestService::func, in); }

#define CHECK_REPEAT_STRING(in) \
    { CheckRepeat(in); }

#define CHECK_REVERSE(func, in) \
    { CheckReverse(&ITestService::func, in); }

TEST_F(BinderTest, aBoolean) {
    CHECK_REPEAT(RepeatBoolean, true);
}

TEST_F(BinderTest, aByte) {
    CHECK_REPEAT(RepeatByte, int8_t{-128});
}

TEST_F(BinderTest, aChar) {
    CHECK_REPEAT(RepeatChar, char16_t{'A'});
}

TEST_F(BinderTest, aInt) {
    CHECK_REPEAT(RepeatInt, int32_t{1 << 30});
}

TEST_F(BinderTest, aLong) {
    CHECK_REPEAT(RepeatLong, int64_t{1LL << 60});
}

TEST_F(BinderTest, aFloat) {
    CHECK_REPEAT(RepeatFloat, float{1.0f / 3.0f});
}

TEST_F(BinderTest, aDouble) {
    CHECK_REPEAT(RepeatDouble, double{1.0 / 3.0});
}

TEST_F(BinderTest, aByteEnum) {
    CHECK_REPEAT(RepeatByteEnum, ByteEnum::BAR);
}

TEST_F(BinderTest, aIntEnum) {
    CHECK_REPEAT(RepeatIntEnum, IntEnum::BAZ);
}

TEST_F(BinderTest, aLongEnum) {
    CHECK_REPEAT(RepeatLongEnum, LongEnum::FOO);
}

TEST_F(BinderTest, byteConstants) {
    constexpr int8_t consts[] = {ITestService::BYTE_TEST_CONSTANT};
    for (const auto& sent : consts) {
        CHECK_REPEAT(RepeatByte, sent);
    }
}

TEST_F(BinderTest, intConstants) {
    constexpr int32_t consts[] = {ITestService::TEST_CONSTANT,   ITestService::TEST_CONSTANT2,
                                  ITestService::TEST_CONSTANT3,  ITestService::TEST_CONSTANT4,
                                  ITestService::TEST_CONSTANT5,  ITestService::TEST_CONSTANT6,
                                  ITestService::TEST_CONSTANT7,  ITestService::TEST_CONSTANT8,
                                  ITestService::TEST_CONSTANT9,  ITestService::TEST_CONSTANT10,
                                  ITestService::TEST_CONSTANT11, ITestService::TEST_CONSTANT12};
    for (const auto& sent : consts) {
        CHECK_REPEAT(RepeatInt, sent);
    }
}

TEST_F(BinderTest, longConstants) {
    constexpr int64_t consts[] = {ITestService::LONG_TEST_CONSTANT};
    for (const auto& sent : consts) {
        CHECK_REPEAT(RepeatLong, sent);
    }
}

TEST_F(BinderTest, strings) {
    std::vector<String16> strings = {
            String16("Deliver us from evil."), String16(), String16("\0\0", 2),
            // This is actually two unicode code points:
            //   U+10437: The 'small letter yee' character in the deseret
            //   alphabet U+20AC: A euro sign
            String16("\xD8\x01\xDC\x37\x20\xAC"), ITestService::STRING_TEST_CONSTANT(),
            ITestService::STRING_TEST_CONSTANT2()};
    for (const auto& sent : strings) {
        CHECK_REPEAT_STRING(sent);
    }
}

TEST_F(BinderTest, booleanArray) {
    std::vector<bool> bools{true, false, false};
    CHECK_REVERSE(ReverseBoolean, bools);
}

TEST_F(BinderTest, byteArray) {
    std::vector<uint8_t> bytes{uint8_t{255}, uint8_t{0}, uint8_t{127}};
    CHECK_REVERSE(ReverseByte, bytes);
}

TEST_F(BinderTest, charArray) {
    std::vector<char16_t> chars{char16_t{'A'}, char16_t{'B'}, char16_t{'C'}};
    CHECK_REVERSE(ReverseChar, chars);
}

TEST_F(BinderTest, intArray) {
    std::vector<int> ints{1, 2, 3};
    CHECK_REVERSE(ReverseInt, ints);
}

TEST_F(BinderTest, longArray) {
    std::vector<int64_t> longs{-1LL, 0LL, int64_t{1LL << 60}};
    CHECK_REVERSE(ReverseLong, longs);
}

TEST_F(BinderTest, floatArray) {
    std::vector<float> floats{-0.3f, -0.7f, 8.0f};
    CHECK_REVERSE(ReverseFloat, floats);
}

TEST_F(BinderTest, doubleArray) {
    std::vector<double> doubles{1.0 / 3.0, 1.0 / 7.0, 42.0};
    CHECK_REVERSE(ReverseDouble, doubles);
}

TEST_F(BinderTest, byteEnumArray) {
    std::vector<ByteEnum> bytes{ByteEnum::BAR, ByteEnum::FOO, ByteEnum::BAZ};
    CHECK_REVERSE(ReverseByteEnum, bytes);
}

TEST_F(BinderTest, byteEnumArray2) {
    std::vector<ByteEnum> bytes{std::begin(android::enum_range<ByteEnum>()),
                                std::end(android::enum_range<ByteEnum>())};
    CHECK_REVERSE(ReverseByteEnum, bytes);
}

TEST_F(BinderTest, intEnumArray) {
    std::vector<IntEnum> ints{IntEnum::BAR, IntEnum::BAZ, IntEnum::FOO};
    CHECK_REVERSE(ReverseIntEnum, ints);
}

TEST_F(BinderTest, longEnumArray) {
    std::vector<LongEnum> longs{LongEnum::BAR, LongEnum::BAZ, LongEnum::FOO};
    CHECK_REVERSE(ReverseLongEnum, longs);
}

// Start a number of threads and make requests in parallel from them
TEST_F(BinderTest, threads) {
    constexpr size_t kMaxTestThreads = 32;
    std::vector<int> ints{42, 1000, 1337};

    struct ThreadResult {
        Status status;
        std::vector<int> reversed;
    };

    std::array<ThreadResult, kMaxTestThreads> threadResults;
    std::vector<std::thread> threads;
    for (size_t i = 0; i < kMaxTestThreads; i++) {
        // Capture i by copy so every thread gets its own index
        threads.emplace_back([this, &ints, &threadResults, i]() {
            std::vector<int> repeated;
            threadResults[i].status =
                    mSrv.get()->ReverseInt(ints, &repeated, &threadResults[i].reversed);
        });
    }

    // Make a copy of ints because the threads might be using the original
    auto reversed = ints;
    std::reverse(reversed.begin(), reversed.end());
    for (size_t i = 0; i < kMaxTestThreads; i++) {
        threads[i].join();
        ASSERT_TRUE(threadResults[i].status.isOk()) << threadResults[i].status;
        ASSERT_EQ(threadResults[i].reversed, reversed);
    }
}

class MyBinderCallbackTest : public BnTestService {
    Status RepeatBoolean(bool token, bool* _aidl_return) override {
        return Repeat(token, _aidl_return);
    }
    Status RepeatByte(int8_t token, int8_t* _aidl_return) override {
        return Repeat(token, _aidl_return);
    }
    Status RepeatChar(char16_t token, char16_t* _aidl_return) override {
        return Repeat(token, _aidl_return);
    }
    Status RepeatInt(int32_t token, int32_t* _aidl_return) override {
        return Repeat(token, _aidl_return);
    }
    Status RepeatLong(int64_t token, int64_t* _aidl_return) override {
        return Repeat(token, _aidl_return);
    }
    Status RepeatFloat(float token, float* _aidl_return) override {
        return Repeat(token, _aidl_return);
    }
    Status RepeatDouble(double token, double* _aidl_return) override {
        return Repeat(token, _aidl_return);
    }
    Status RepeatString(const String16& token, String16* _aidl_return) override {
        return Repeat(token, _aidl_return);
    }
    Status RepeatByteEnum(ByteEnum token, ByteEnum* _aidl_return) override {
        return Repeat(token, _aidl_return);
    }
    Status RepeatIntEnum(IntEnum token, IntEnum* _aidl_return) override {
        return Repeat(token, _aidl_return);
    }
    Status RepeatLongEnum(LongEnum token, LongEnum* _aidl_return) override {
        return Repeat(token, _aidl_return);
    }

    Status ReverseBoolean(const std::vector<bool>& input, std::vector<bool>* repeated,
                          std::vector<bool>* _aidl_return) override {
        return ReverseArray(input, repeated, _aidl_return);
    }
    Status ReverseByte(const std::vector<uint8_t>& input, std::vector<uint8_t>* repeated,
                       std::vector<uint8_t>* _aidl_return) override {
        return ReverseArray(input, repeated, _aidl_return);
    }
    Status ReverseChar(const std::vector<char16_t>& input, std::vector<char16_t>* repeated,
                       std::vector<char16_t>* _aidl_return) override {
        return ReverseArray(input, repeated, _aidl_return);
    }
    Status ReverseInt(const std::vector<int32_t>& input, std::vector<int32_t>* repeated,
                      std::vector<int32_t>* _aidl_return) override {
        return ReverseArray(input, repeated, _aidl_return);
    }
    Status ReverseLong(const std::vector<int64_t>& input, std::vector<int64_t>* repeated,
                       std::vector<int64_t>* _aidl_return) override {
        return ReverseArray(input, repeated, _aidl_return);
    }
    Status ReverseFloat(const std::vector<float>& input, std::vector<float>* repeated,
                        std::vector<float>* _aidl_return) override {
        return ReverseArray(input, repeated, _aidl_return);
    }
    Status ReverseDouble(const std::vector<double>& input, std::vector<double>* repeated,
                         std::vector<double>* _aidl_return) override {
        return ReverseArray(input, repeated, _aidl_return);
    }
    Status ReverseString(const std::vector<String16>& input, std::vector<String16>* repeated,
                         std::vector<String16>* _aidl_return) override {
        return ReverseArray(input, repeated, _aidl_return);
    }
    Status ReverseByteEnum(const std::vector<ByteEnum>& input, std::vector<ByteEnum>* repeated,
                           std::vector<ByteEnum>* _aidl_return) override {
        return ReverseArray(input, repeated, _aidl_return);
    }
    Status ReverseIntEnum(const std::vector<IntEnum>& input, std::vector<IntEnum>* repeated,
                          std::vector<IntEnum>* _aidl_return) override {
        return ReverseArray(input, repeated, _aidl_return);
    }
    Status ReverseLongEnum(const std::vector<LongEnum>& input, std::vector<LongEnum>* repeated,
                           std::vector<LongEnum>* _aidl_return) override {
        return ReverseArray(input, repeated, _aidl_return);
    }

    Status nestMe(const sp<ITestService>& binder, int count) override {
        if (count <= 0) return Status::ok();
        return binder->nestMe(this, count - 1);
    }

  private:
    template <typename T>
    Status Repeat(const T& in, T* out) {
        *out = in;
        return Status::ok();
    }
};

TEST_F(BinderTest, nestedCall) {
    auto nastyNester = sp<MyBinderCallbackTest>::make();
    auto status = mSrv->nestMe(nastyNester, 10);
    ASSERT_TRUE(status.isOk()) << status;
}

}  // namespace android
