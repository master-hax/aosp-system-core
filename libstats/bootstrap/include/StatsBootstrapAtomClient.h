/*
 * Copyright (C) 2021 The Android Open Source Project
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

#pragma once

#include <aidl/android/os/StatsBootstrapAtom.h>

namespace android {
namespace os {
namespace stats {

class StatsBootstrapAtomClient {
  public:
    static StatsBootstrapAtomClient& getInstance();

    status_t reportBootstrapAtom(const StatsBootstrapAtom& atom);

  private:
    mutable std::mutex mLock;
    sp<IStatsBootstrapAtomService> mService;

    sp<IStatsBootstrapAtomService> getStatsBootstrapAtomServiceNonBlocking();

    void bootstrapAtomServiceDied(const wp<IBinder>& who);
}

}  // namespace stats
}  // namespace os
}  // namespace android