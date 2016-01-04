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

#include "metrics_collector_service_impl.h"

#include <binder/IServiceManager.h>
#include <binder/Status.h>
#include <brillo/binder_watcher.h>
#include <utils/Errors.h>

#include "metrics_collector.h"

using namespace android;

BnMetricsCollectorServiceImpl::BnMetricsCollectorServiceImpl(
    MetricsCollector* metrics_collector) {
  metrics_collector_ = metrics_collector;
}

void BnMetricsCollectorServiceImpl::Run() {
  status_t status =
      defaultServiceManager()->addService(getInterfaceDescriptor(), this);
  CHECK(status == OK) << "libmetricscollectorservice: failed to add service";
  binder_watcher_.reset(new ::brillo::BinderWatcher);
  CHECK(binder_watcher_->Init()) << "Binder FD watcher init failed";
}

android::binder::Status BnMetricsCollectorServiceImpl::notifyUserCrash() {
  metrics_collector_->ProcessUserCrash();
  return android::binder::Status::ok();
}
