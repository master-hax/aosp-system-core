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

#include <aidl/android/os/IStatsBootstrapAtomService.h>
#include <binder/IServiceManager.h>
#include <utils/Errors.h>

namespace android {
namespace os {
namespace stats {

class DeathObserver : public IBinder::DeathRecipient {
    void binderDied(const wp<IBinder>& who) { mClient.bootstrapAtomServiceDied(who); }

  private:
    StatsBootstrapAtomClient& mClient;

} StatsBootstrapAtomClient& StatsBootstrapAtomClient::getInstance() {
    static StatsBootstrapAtomClient client;
    return client;
}

status_t StatsBootstrapAtomClient::reportBootstrapAtom(const StatsBootstrapAtom& atom) {
    sp<IStatsBootstrapAtomService> service = getBootstrapAtomServiceNonBlocking();
    if (service == nullptr) {
        return WOULD_BLOCK;
    }
    return service->reportBootstrapAtom(atom);
}

sp<IStatsBootstrapAtomService> StatsBootstrapAtomClient::getBootstrapAtomServiceNonBlocking() {
    lock_guard<std::mutex> lock(mLock);
    if (mService != nullptr) {
        return mService;
    }
    mService = checkDeclaredService("statsbootstrap");
    if (mService != nullptr) {
        // Set up binder death.
    }
}

}  // namespace stats
}  // namespace os
}  // namespace android