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

#include "android/brillo/BnMetricsService.h"

class BinderService : public android::brillo::BnMetricsService {

 public:
  BinderService();
  virtual ~BinderService();

  void Run();
  
  android::binder::Status recordHistogram(const android::String16& name,
                                          int sample,
                                          int min,
                                          int max,
                                          int nbuckets) override;

  android::binder::Status recordLinearHistogram(const android::String16& name,
                                                int sample,
                                                int max) override;

  android::binder::Status recordSparseHistogram(const android::String16& name,
                                                int sample) override;

  android::binder::Status recordUserAction(
      const android::String16& name) override;

  android::binder::Status recordCrash(
      const android::String16& crash_type) override;
};
