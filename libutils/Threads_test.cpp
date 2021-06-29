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

#include <gtest/gtest.h>
#include <log/log.h>
#include <utils/AndroidThreads.h>
#include <utils/Thread.h>

#include <chrono>
#include <memory>
#include <mutex>

using std::chrono_literals::operator""ms;

namespace android {

#if !defined(_WIN32)

namespace {

class Userdata {
  public:
    Userdata(int preHook, int func, int postHook)
        : preHookRet(preHook), funcRet(func), postHookRet(postHook) {}

    static int preHook(void* data, const char*) {
        auto udata = static_cast<Userdata*>(data);
        {
            std::lock_guard<std::mutex> lock(udata->mutex);
            udata->preHookCalled = true;
        }
        udata->cv.notify_all();
        return udata->preHookRet;
    }

    static int func(void* data) {
        auto udata = static_cast<Userdata*>(data);
        {
            std::lock_guard<std::mutex> lock(udata->mutex);
            // Userdata::func should only be invoked if pre hook passes.
            if (udata->preHookRet == 0 && !udata->preHookCalled) return -1;
            udata->funcCalled = true;
        }
        udata->cv.notify_all();
        return udata->funcRet;
    }

    static int postHook(void* data, const char*) {
        auto udata = static_cast<Userdata*>(data);
        {
            std::lock_guard<std::mutex> lock(udata->mutex);
            // post hook should be invoked regardless of whether the function fails or not.
            if (!udata->funcCalled) return -1;
            udata->postHookCalled = true;
        }
        udata->cv.notify_all();
        return udata->postHookRet;
    }

    // Value returned by pre-hook. If 0, expect pre-hook exists and be called.
    int preHookRet;
    // Value returned by the entry function.
    int funcRet;
    // Value returned by post-hook. If 0, expect post-hook exists and be called.
    int postHookRet;

    std::mutex mutex;  // for below
    std::condition_variable cv;
    bool preHookCalled = false;
    bool funcCalled = false;
    bool postHookCalled = false;
};

class ThreadHooks : public ::testing::Test {
  public:
    void SetUp() override {
        setThreadPreHook(nullptr, nullptr);
        setThreadPostHook(nullptr, nullptr);
    }
    void TearDown() override {
        // If any failures, the detached thread could still be running, so intentionally leak
        // userdata to prevent segmentation fault.
        if (::testing::Test::HasFailure()) junk.emplace_back(std::move(userdata));

        setThreadPreHook(nullptr, nullptr);
        setThreadPostHook(nullptr, nullptr);
    }

    std::unique_ptr<Userdata> userdata;

  private:
    static std::vector<std::unique_ptr<Userdata>> junk;
};
std::vector<std::unique_ptr<Userdata>> ThreadHooks::junk;

TEST_F(ThreadHooks, PreHook) {
    userdata = std::make_unique<Userdata>(0, 0, 1);
    setThreadPreHook(Userdata::preHook, userdata.get());
    ASSERT_TRUE(createThread(Userdata::func, userdata.get()));

    std::unique_lock<std::mutex> lock(userdata->mutex);
    EXPECT_TRUE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->preHookCalled; }));
    EXPECT_TRUE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->funcCalled; }));
}

TEST_F(ThreadHooks, PreHookFails) {
    userdata = std::make_unique<Userdata>(1, 0, 1);
    setThreadPreHook(Userdata::preHook, userdata.get());
    ASSERT_TRUE(createThread(Userdata::func, userdata.get()));

    std::unique_lock<std::mutex> lock(userdata->mutex);
    EXPECT_TRUE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->preHookCalled; }));
    EXPECT_FALSE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->funcCalled; }))
            << "pre hook fails, function should not execute at all.";
}

TEST_F(ThreadHooks, PostHook) {
    userdata = std::make_unique<Userdata>(1, 0, 0);
    setThreadPostHook(Userdata::postHook, userdata.get());
    ASSERT_TRUE(createThread(Userdata::func, userdata.get()));

    std::unique_lock<std::mutex> lock(userdata->mutex);
    EXPECT_TRUE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->funcCalled; }));
    EXPECT_TRUE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->postHookCalled; }));
}

TEST_F(ThreadHooks, PostHookFuncFails) {
    userdata = std::make_unique<Userdata>(1, 1, 0);
    setThreadPostHook(Userdata::postHook, userdata.get());
    ASSERT_TRUE(createThread(Userdata::func, userdata.get()));

    std::unique_lock<std::mutex> lock(userdata->mutex);
    EXPECT_TRUE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->funcCalled; }));
    EXPECT_TRUE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->postHookCalled; }))
            << "Entry function fails. Post hook should still be called but it is not.";
}

TEST_F(ThreadHooks, BothHooks) {
    userdata = std::make_unique<Userdata>(0, 0, 0);
    setThreadPreHook(Userdata::preHook, userdata.get());
    setThreadPostHook(Userdata::postHook, userdata.get());
    ASSERT_TRUE(createThread(Userdata::func, userdata.get()));

    std::unique_lock<std::mutex> lock(userdata->mutex);
    EXPECT_TRUE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->preHookCalled; }));
    EXPECT_TRUE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->funcCalled; }));
    EXPECT_TRUE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->postHookCalled; }));
}

TEST_F(ThreadHooks, BothHooksWithFailedPreHook) {
    userdata = std::make_unique<Userdata>(1, 0, 0);
    setThreadPreHook(Userdata::preHook, userdata.get());
    setThreadPostHook(Userdata::postHook, userdata.get());
    ASSERT_TRUE(createThread(Userdata::func, userdata.get()));

    std::unique_lock<std::mutex> lock(userdata->mutex);
    EXPECT_TRUE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->preHookCalled; }));
    EXPECT_FALSE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->funcCalled; }))
            << "pre hook fails, function should not execute at all.";
    EXPECT_FALSE(userdata->cv.wait_for(lock, 200ms, [&] { return userdata->postHookCalled; }))
            << "pre hook fails, post hook should not execute at all.";
}

}  // namespace

#endif  // !_WIN32

}  // namespace android
