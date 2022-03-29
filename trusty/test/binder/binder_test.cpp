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
#include <binder/RpcTransportTipcAndroid.h>
#include <gtest/gtest.h>
#include <stdint.h>
#include <trusty/tipc.h>

namespace android {

constexpr const char kTrustyDefaultDeviceName[] = "/dev/trusty-ipc-dev0";

static void getTestService(sp<ITestService>* outSrv) {
    auto sess = RpcSession::make(RpcTransportCtxFactoryTipcAndroid::make());
    auto status = sess->setupPreconnectedClient({}, []() {
        // TODO: make device name configurable
        int tipcFd = tipc_connect(kTrustyDefaultDeviceName, ITestService::PORT().c_str());
        return tipcFd >= 0 ? base::unique_fd(tipcFd) : base::unique_fd();
    });
    ASSERT_EQ(status, OK);

    auto root = sess->getRootObject();
    ASSERT_NE(root.get(), nullptr);

    auto testSrv = ITestService::asInterface(root);
    ASSERT_NE(testSrv.get(), nullptr);

    *outSrv = std::move(testSrv);
}

class TrustyBinderTest : public testing::Test {
  protected:
    void SetUp() override { getTestService(&mSrv); }

    template <typename T, typename U, typename V>
    void CheckRepeat(binder::Status (ITestService::*func)(T, U*), V in) {
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
    void CheckReverse(binder::Status (ITestService::*func)(const std::vector<T>&, std::vector<T>*,
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

    sp<ITestService> mSrv;
};

#define CHECK_REPEAT(func, in) \
    { CheckRepeat(&ITestService::func, in); }

#define CHECK_REPEAT_STRING(in) \
    { CheckRepeat(in); }

#define CHECK_REVERSE(func, in) \
    { CheckReverse(&ITestService::func, in); }

TEST_F(TrustyBinderTest, RepeatBoolean) {
    CHECK_REPEAT(RepeatBoolean, true);
}

TEST_F(TrustyBinderTest, RepeatByte) {
    CHECK_REPEAT(RepeatByte, int8_t{-128});
}

TEST_F(TrustyBinderTest, RepeatChar) {
    CHECK_REPEAT(RepeatChar, char16_t{'A'});
}

TEST_F(TrustyBinderTest, RepeatInt) {
    CHECK_REPEAT(RepeatInt, int32_t{1 << 30});
}

TEST_F(TrustyBinderTest, RepeatLong) {
    CHECK_REPEAT(RepeatLong, int64_t{1LL << 60});
}

TEST_F(TrustyBinderTest, RepeatFloat) {
    CHECK_REPEAT(RepeatFloat, float{1.0f / 3.0f});
}

TEST_F(TrustyBinderTest, RepeatDouble) {
    CHECK_REPEAT(RepeatDouble, double{1.0 / 3.0});
}

TEST_F(TrustyBinderTest, RepeatByteEnum) {
    CHECK_REPEAT(RepeatByteEnum, ByteEnum::BAR);
}

TEST_F(TrustyBinderTest, RepeatIntEnum) {
    CHECK_REPEAT(RepeatIntEnum, IntEnum::BAZ);
}

TEST_F(TrustyBinderTest, RepeatLongEnum) {
    CHECK_REPEAT(RepeatLongEnum, LongEnum::FOO);
}

TEST_F(TrustyBinderTest, RepeatByteConstants) {
    constexpr int8_t consts[] = {ITestService::BYTE_TEST_CONSTANT};
    for (const auto& sent : consts) {
        CHECK_REPEAT(RepeatByte, sent);
    }
}

TEST_F(TrustyBinderTest, RepeatIntConstants) {
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

TEST_F(TrustyBinderTest, RepeatLongConstants) {
    constexpr int64_t consts[] = {ITestService::LONG_TEST_CONSTANT};
    for (const auto& sent : consts) {
        CHECK_REPEAT(RepeatLong, sent);
    }
}

TEST_F(TrustyBinderTest, RepeatStrings) {
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

TEST_F(TrustyBinderTest, ReverseBooleanArray) {
    std::vector<bool> bools{true, false, false};
    CHECK_REVERSE(ReverseBoolean, bools);
}

TEST_F(TrustyBinderTest, ReverseByteArray) {
    std::vector<uint8_t> bytes{uint8_t{255}, uint8_t{0}, uint8_t{127}};
    CHECK_REVERSE(ReverseByte, bytes);
}

TEST_F(TrustyBinderTest, ReverseCharArray) {
    std::vector<char16_t> chars{char16_t{'A'}, char16_t{'B'}, char16_t{'C'}};
    CHECK_REVERSE(ReverseChar, chars);
}

TEST_F(TrustyBinderTest, ReverseIntArray) {
    std::vector<int> ints{1, 2, 3};
    CHECK_REVERSE(ReverseInt, ints);
}

TEST_F(TrustyBinderTest, ReverseLongArray) {
    std::vector<int64_t> longs{-1LL, 0LL, int64_t{1LL << 60}};
    CHECK_REVERSE(ReverseLong, longs);
}

TEST_F(TrustyBinderTest, ReverseFloatArray) {
    std::vector<float> floats{-0.3f, -0.7f, 8.0f};
    CHECK_REVERSE(ReverseFloat, floats);
}

TEST_F(TrustyBinderTest, ReverseDoubleArray) {
    std::vector<double> doubles{1.0 / 3.0, 1.0 / 7.0, 42.0};
    CHECK_REVERSE(ReverseDouble, doubles);
}

TEST_F(TrustyBinderTest, ReverseByteEnumArray) {
    std::vector<ByteEnum> bytes{ByteEnum::BAR, ByteEnum::FOO, ByteEnum::BAZ};
    CHECK_REVERSE(ReverseByteEnum, bytes);
}

TEST_F(TrustyBinderTest, ReverseByteEnumArray2) {
    std::vector<ByteEnum> bytes{std::begin(android::enum_range<ByteEnum>()),
                                std::end(android::enum_range<ByteEnum>())};
    CHECK_REVERSE(ReverseByteEnum, bytes);
}

TEST_F(TrustyBinderTest, ReverseIntEnumArray) {
    std::vector<IntEnum> ints{IntEnum::BAR, IntEnum::BAZ, IntEnum::FOO};
    CHECK_REVERSE(ReverseIntEnum, ints);
}

TEST_F(TrustyBinderTest, ReverseLongEnumArray) {
    std::vector<LongEnum> longs{LongEnum::BAR, LongEnum::BAZ, LongEnum::FOO};
    CHECK_REVERSE(ReverseLongEnum, longs);
}

// Start a number of threads each with its own separate session
// and make a concurrent request from each one
TEST(TrustyBinderThreadsTest, ManySessions) {
    constexpr size_t kMaxTestThreads = 32;
    std::vector<int> ints{42, 1000, 1337};

    struct ThreadState {
        sp<ITestService> service;
        binder::Status status;
        std::vector<int> reversed;
    };

    std::array<ThreadState, kMaxTestThreads> threadState;
    for (size_t i = 0; i < kMaxTestThreads; i++) {
        // Connect to the services on the main thread so we catch the
        // exceptions from ASSERT*
        getTestService(&threadState[i].service);
    }

    // TODO: replace this with std::barrier when we get C++20
    std::mutex barrierMutex;
    std::condition_variable barrierCv;
    size_t barrierThreads;
    std::vector<std::thread> threads;
    for (size_t i = 0; i < kMaxTestThreads; i++) {
        auto threadFn = [&](ThreadState& state) {
            // Force the threads to send requests simultaneously
            {
                // Manual barrier implementation since we don't have
                // std::barrier yet (it was added in C++20)
                std::unique_lock lock(barrierMutex);
                barrierThreads++;
                if (barrierThreads < kMaxTestThreads) {
                    // More threads after this one
                    barrierCv.wait(lock, [&] { return barrierThreads == kMaxTestThreads; });
                } else {
                    // This is the last thread, wake up all the others
                    lock.unlock();
                    barrierCv.notify_all();
                }
            }

            std::vector<int> repeated;
            state.status = state.service->ReverseInt(ints, &repeated, &state.reversed);
        };
        threads.emplace_back(threadFn, std::ref(threadState[i]));
    }

    // Make a copy of ints because the threads might be using the original
    auto reversed = ints;
    std::reverse(reversed.begin(), reversed.end());
    for (size_t i = 0; i < kMaxTestThreads; i++) {
        threads[i].join();
        ASSERT_TRUE(threadState[i].status.isOk()) << threadState[i].status;
        ASSERT_EQ(threadState[i].reversed, reversed);
    }
}

}  // namespace android
