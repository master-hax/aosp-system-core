/*
 * Copyright (C) 2019 The Android Open Source Project
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
#include <android/system/suspend/1.0/ISystemSuspend.h>
#include <wakelock/wakelock.h>

#include <mutex>

using android::sp;
using android::system::suspend::V1_0::ISystemSuspend;
using android::system::suspend::V1_0::IWakeLock;
using android::system::suspend::V1_0::WakeLockType;

namespace android {
namespace wakelock {

class WakeLock::WakeLockImpl {
  public:
    WakeLockImpl(const std::string& name);
    ~WakeLockImpl();

  private:
    sp<IWakeLock> mWakeLock;
};

WakeLock::WakeLock(const std::string& name) : mImpl(std::make_unique<WakeLockImpl>(name)) {}

WakeLock::~WakeLock() = default;

WakeLock::WakeLockImpl::WakeLockImpl(const std::string& name) : mWakeLock(nullptr) {
    static sp<ISystemSuspend> suspendService = ISystemSuspend::getService();
    mWakeLock = suspendService->acquireWakeLock(WakeLockType::PARTIAL, name);
}

WakeLock::WakeLockImpl::~WakeLockImpl() {
    auto ret = mWakeLock->release();
    if (!ret.isOk()) {
        LOG(ERROR) << "IWakeLock::release() call failed: " << ret.description();
    }
}

}  // namespace wakelock
}  // namespace android
