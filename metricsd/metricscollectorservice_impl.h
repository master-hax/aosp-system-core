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

#ifndef METRICSD_METRICSCOLLECTORSERVICE_IMPL_H_
#define METRICSD_METRICSCOLLECTORSERVICE_IMPL_H_

// metrics_collector binder service implementation.  Constructed by
// MetricsCollectorServiceTrampoline, which we use to call back into
// MetricsCollector.  The trampoline isolates us from the -frtti code of
// metrics_collector / libbrillo.

#include "android/brillo/metrics/BnMetricsCollectorService.h"
#include "metricscollectorservice_trampoline.h"

#include <binder/Status.h>

class BnMetricsCollectorServiceImpl : public
   android::brillo::metrics::BnMetricsCollectorService {
 public:

  // Passed a this pointer from the MetricsCollectorServiceTrampoline
  // object that constructs us.
  BnMetricsCollectorServiceImpl(MetricsCollectorServiceTrampoline*
                                metricscollectorservice_trampoline);
  virtual ~BnMetricsCollectorServiceImpl() = default;

  // Starts the binder main loop.
  void Run();

  // Called by crash_reporter to report a userspace crash event.  We relay
  // this to MetricsCollector using the trampoline.
  android::binder::Status notifyUserCrash();

 private:
  MetricsCollectorServiceTrampoline* metricscollectorservice_trampoline_;
};

#endif  // METRICSD_METRICSCOLLECTORSERVICE_IMPL_H_
