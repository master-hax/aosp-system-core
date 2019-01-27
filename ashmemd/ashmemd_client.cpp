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

#include <android/ashmemd/IAshmemDeviceService.h>
#include <binder/IServiceManager.h>

using android::IBinder;
using android::IServiceManager;
using android::String16;
using android::ashmemd::IAshmemDeviceService;
using android::os::ParcelFileDescriptor;

namespace android {
namespace ashmemd {

sp<IAshmemDeviceService> getAshmemService() {
    sp<IServiceManager> sm = android::defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("ashmem_device_service"));
    if (binder) {
        return interface_cast<IAshmemDeviceService>(binder);
    }
    return nullptr;
}

extern "C" int openAshmemdFd() {
    static sp<IAshmemDeviceService> ashmemService = getAshmemService();
    if (!ashmemService) return -1;

    ParcelFileDescriptor fd;
    auto status = ashmemService->open(&fd);
    if (!status.isOk()) return -1;

    return dup(fd.get());
}

}  // namespace ashmemd
}  // namespace android
