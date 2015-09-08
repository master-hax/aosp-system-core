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

#ifndef SYSTEM_CORE_INCLUDE_BINDERWRAPPER_STUB_BINDER_WRAPPER_H_
#define SYSTEM_CORE_INCLUDE_BINDERWRAPPER_STUB_BINDER_WRAPPER_H_

#include <map>
#include <string>

#include <base/macros.h>
#include <binderwrapper/binder_wrapper.h>

namespace android {

// Stub implementation of BinderWrapper for testing.
//
// Example usage:
//
// First, assuming a base IFoo binder interface, create a stub class that
// derives from BnFoo to implement the receiver side of the communication:
//
//   class StubFoo : public BnFoo {
//    public:
//     ...
//     status_t doSomething(int arg) override {
//       // e.g. save passed-in value for later inspection by tests.
//       return OK;
//     }
//   };
//
// Next, from your test code, inject a StubBinderManager either directly or by
// inheriting from the BinderTestBase class:
//
//   StubBinderWrapper* wrapper = new StubBinderWrapper();
//   BinderWrapper::InitForTesting(wrapper);  // Takes ownership.
//
// Also from your test, create a StubFoo and register it with the wrapper:
//
//   StubFoo* foo = new StubFoo();
//   sp<IBinder> binder(foo);
//   wrapper->SetBinderForService("foo", binder);
//
// The code being tested can now use the wrapper to get the stub and call it:
//
//   sp<IBinder> binder = BinderWrapper::Get()->GetService("foo");
//   CHECK(binder.get());
//   sp<IFoo> foo = interface_cast<IFoo>(binder);
//   CHECK_EQ(foo->doSomething(3), OK);
//
class StubBinderWrapper : public BinderWrapper {
 public:
  StubBinderWrapper();
  ~StubBinderWrapper() override;

  // Sets the binder to return when |service_name| is passed to GetService() or
  // WaitForService().
  void SetBinderForService(const std::string& service_name,
                           const sp<IBinder>& binder);

  // BinderWrapper:
  sp<IBinder> GetService(const std::string& service_name) override;
  bool RegisterService(const std::string& service_name,
                       const sp<IBinder>& binder) override;
  bool RegisterForDeathNotifications(const sp<IBinder>& binder,
                                     const base::Closure& callback) override;
  bool UnregisterForDeathNotifications(const sp<IBinder>& binder) override;

 private:
  // Map from service name to associated binder handle. Used by GetService() and
  // WaitForService().
  std::map<std::string, sp<IBinder>> services_to_return_;

  // Map from service name to associated binder handle. Updated by
  // RegisterService().
  std::map<std::string, sp<IBinder>> registered_services_;

  // Map from binder handle to the callback that should be invoked on binder
  // death.
  std::map<sp<IBinder>, base::Closure> death_callbacks_;

  DISALLOW_COPY_AND_ASSIGN(StubBinderWrapper);
};

}  // namespace android

#endif  // SYSTEM_CORE_INCLUDE_BINDERWRAPPER_STUB_BINDER_WRAPPER_H_
