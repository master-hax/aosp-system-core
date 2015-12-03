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

#ifndef METRICS_METRICSCOLLECTORSERVICE_TRAMPOLINE_H_
#define METRICS_METRICSCOLLECTORSERVICE_TRAMPOLINE_H_

// Trampoline between the -fno-rtti compile of libmetricsservice and the
// -frtti compile of metrics_collector.  MetricsCollectorServiceTrampoline
// is called from MetricsCollector to run the IMetricsCollectorService
// server, and acts as a go-between for calls from server back to
// MetricsCollector.

// Forward declaration of the binder service implementation.  A circular
// dependency exists between that class and our class.
class BnMetricsCollectorServiceImpl;

class MetricsCollectorServiceTrampoline {
 public:

  // Constructor take a this pointer from the MetricsCollector class that
  // constructs these objects, passed as a void* to avoid pulling a -frtti
  // header file chain into the non-rtti sources.
  MetricsCollectorServiceTrampoline(void* metrics_collector);

  // Initialize and run the IMetricsCollectorService
  void Run();

  // Called from IMetricsCollectorService to trampoline into the
  // MetricsCollector method of the same name.
  void ProcessUserCrash();

 private:

  // The IMetricsCollectorService implementation we construct.
  BnMetricsCollectorServiceImpl* metricscollectorservice;
};

#endif  // METRICS_METRICSCOLLECTORSERVICE_TRAMPOLINE_H_
