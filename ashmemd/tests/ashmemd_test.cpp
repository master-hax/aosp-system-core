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

#include <android-base/unique_fd.h>
#include <binder/IServiceManager.h>
#include <gtest/gtest.h>

#include <android/ashmemd/IAshmemDeviceService.h>

using android::IBinder;
using android::IServiceManager;
using android::String16;
using android::ashmemd::IAshmemDeviceService;
using android::base::unique_fd;

namespace android {
namespace ashmemd {

TEST(AshmemdTest, GetAshmemDeviceFD) {
    sp<IServiceManager> sm = android::defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("ashmem_device_service"));
    ASSERT_NE(binder, nullptr);

    sp<IAshmemDeviceService> service = android::interface_cast<IAshmemDeviceService>(binder);
    ASSERT_NE(service, nullptr);

    unique_fd ashmemFd;
    auto status = service->open(&ashmemFd);
    ASSERT_TRUE(status.isOk());
    ASSERT_GE(ashmemFd, 0);
}

}  // namespace ashmemd
}  // namespace android
