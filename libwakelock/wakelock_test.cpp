/*
 * Copyright 2019 The Android Open Source Project
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

#include <android/system/suspend/ISuspendControlService.h>
#include <binder/IServiceManager.h>
#include <gtest/gtest.h>
#include <wakelock/wakelock.h>

#include <thread>

using android::sp;
using android::system::suspend::ISuspendControlService;
using android::system::suspend::WakeLockInfo;
using namespace std::chrono_literals;

namespace android {

class WakeLockTest : public ::testing::Test {
  public:
    virtual void SetUp() override {
        sp<IBinder> control =
                android::defaultServiceManager()->getService(android::String16("suspend_control"));
        ASSERT_NE(control, nullptr) << "failed to get the suspend control service";
        controlService = interface_cast<ISuspendControlService>(control);
    }

    // Returns true iff found.
    bool findWakeLockInfoByName(const sp<ISuspendControlService>& service, const std::string& name,
                                WakeLockInfo* info) {
        std::vector<WakeLockInfo> wlStats;
        service->getWakeLockStats(&wlStats);
        auto it = std::find_if(wlStats.begin(), wlStats.end(),
                               [&name](const auto& x) { return x.name == name; });
        if (it != wlStats.end()) {
            *info = *it;
            return true;
        }
        return false;
    }

    // All userspace wake locks are registered with system suspend.
    sp<ISuspendControlService> controlService;
};

// Test RAII properties of WakeLock destructor.
TEST_F(WakeLockTest, WakeLockDestructor) {
    auto name = std::to_string(rand());
    {
        android::wakelock::WakeLock wl{name};

        WakeLockInfo info;
        auto success = findWakeLockInfoByName(controlService, name, &info);
        ASSERT_TRUE(success);
        ASSERT_EQ(info.name, name);
        ASSERT_EQ(info.pid, getpid());
        ASSERT_TRUE(info.isActive);
    }

    // SystemSuspend receives wake lock release requests on hwbinder thread, while stats requests
    // come on binder thread. Sleep to make sure that stats are reported *after* wake lock release.
    std::this_thread::sleep_for(1ms);
    WakeLockInfo info;
    auto success = findWakeLockInfoByName(controlService, name, &info);
    ASSERT_TRUE(success);
    ASSERT_EQ(info.name, name);
    ASSERT_EQ(info.pid, getpid());
    ASSERT_FALSE(info.isActive);
}

TEST_F(WakeLockTest, WakeLockRelease) {
    auto name = std::to_string(rand());
    android::wakelock::WakeLock wl{name};

    WakeLockInfo info;
    auto success = findWakeLockInfoByName(controlService, name, &info);
    ASSERT_TRUE(success);
    ASSERT_EQ(info.name, name);
    ASSERT_EQ(info.pid, getpid());
    ASSERT_TRUE(info.isActive);

    wl.release();

    std::this_thread::sleep_for(1ms);
    success = findWakeLockInfoByName(controlService, name, &info);
    ASSERT_TRUE(success);
    ASSERT_EQ(info.name, name);
    ASSERT_EQ(info.pid, getpid());
    ASSERT_FALSE(info.isActive);
}

}  // namespace android
