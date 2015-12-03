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

#include "metricscollectorservice_impl.h"
#include "metricscollectorservice_trampoline.h"

#include <base/logging.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Status.h>
#include <utils/Errors.h>

using namespace android;

BnMetricsCollectorServiceImpl::BnMetricsCollectorServiceImpl(
    MetricsCollectorServiceTrampoline* metricscollectorservice_trampoline) {
  metricscollectorservice_trampoline_ = metricscollectorservice_trampoline;
}

void BnMetricsCollectorServiceImpl::Run() {
  status_t status =
      defaultServiceManager()->addService(getInterfaceDescriptor(), this);

  if (status != OK) {
    LOG(ERROR) << "libmetricscollectorservice: failed to add service: "
               << status;
    return;
  }

  ProcessState::self()->setThreadPoolMaxThreadCount(0);
  IPCThreadState::self()->disableBackgroundScheduling(true);
  ProcessState::self()->startThreadPool();
  IPCThreadState::self()->joinThreadPool();
}

android::binder::Status BnMetricsCollectorServiceImpl::notifyUserCrash() {
  metricscollectorservice_trampoline_->ProcessUserCrash();
  return android::binder::Status::ok();
}
