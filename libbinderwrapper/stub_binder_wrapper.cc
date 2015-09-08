/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <binderwrapper/stub_binder_wrapper.h>

#include <base/logging.h>
#include <binder/IBinder.h>

namespace android {

StubBinderWrapper::StubBinderWrapper() = default;

StubBinderWrapper::~StubBinderWrapper() = default;

void StubBinderWrapper::SetBinderForService(const std::string& service_name,
                                            const sp<IBinder>& binder) {
  services_to_return_[service_name] = binder;
}

sp<IBinder> StubBinderWrapper::GetService(const std::string& service_name) {
  const auto it = services_to_return_.find(service_name);
  return it != services_to_return_.end() ? it->second : sp<IBinder>();
}

sp<IBinder> StubBinderWrapper::WaitForService(const std::string& service_name) {
  return GetService(service_name);
}

bool StubBinderWrapper::RegisterService(const std::string& service_name,
                                        const sp<IBinder>& binder) {
  registered_services_[service_name] = binder;
  return true;
}

bool StubBinderWrapper::RegisterForDeathNotifications(
    const sp<IBinder>& binder,
    const base::Closure& callback) {
  death_callbacks_[binder] = callback;
  return true;
}

bool StubBinderWrapper::UnregisterForDeathNotifications(
    const sp<IBinder>& binder) {
  death_callbacks_.erase(binder);
  return true;
}

}  // namespace android
