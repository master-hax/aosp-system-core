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

#ifndef METRICSD_UPLOADER_BINDER_SERVICE_H_
#define METRICSD_UPLOADER_BINDER_SERVICE_H_

#include "android/brillo/BnMetricsService.h"

class BinderService : public android::brillo::BnMetricsService {
 public:
  BinderService();
  virtual ~BinderService();

  // Starts the binder main loop.
  void Run();

  // Records an histogram.
  android::binder::Status recordHistogram(const android::String16& name,
                                          int sample, int min, int max,
                                          int nbuckets) override;

  // Records a linear histogram.
  android::binder::Status recordLinearHistogram(const android::String16& name,
                                                int sample, int max) override;

  // Records a sparse histogram.
  android::binder::Status recordSparseHistogram(const android::String16& name,
                                                int sample) override;
};

#endif  // METRICSD_UPLOADER_BINDER_SERVICE_H_
