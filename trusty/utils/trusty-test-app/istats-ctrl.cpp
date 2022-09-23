/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <BnStats.h>
#include <IStats.h>
#include <IStatsProxy.h>
#include <android-base/expected.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransportRaw.h>
#include <binder/RpcTransportTipcAndroid.h>
#include <binder/RpcTrusty.h>
#include <trusty/tipc.h>

#include <android-base/logging.h>

using namespace android;
using android::base::unique_fd;
using android::binder::Status;

constexpr const char kTrustyDefaultDeviceName[] = "/dev/trusty-ipc-dev0";

class Stats : public BnStats {
  public:
    Status reportVendorAtom(const ::VendorAtom& vendorAtom) {
        (void)vendorAtom;
        printf("---NW reportVendorAtom done!!\n");
        return Status::ok();
    }
};

int main(void) {
    fprintf(stderr, "in istats NW test\n");

    // Commenting out the server portion because we do not have any direct incoming call
    // Calls from TA are currently being handle on the extra thread on the session.
    // android::sp<::android::RpcServer> server =
    // ::android::RpcServer::make(::android::RpcTransportCtxFactoryRaw::make());

    auto statsBinderObject = android::sp<Stats>::make();

    // Increasing number of incoming threads on session to be able to receive callbacks
    std::function<void(sp<RpcSession>&)> session_initializer = [](auto session) {
        session->setMaxIncomingThreads(1);
    };

    auto session = RpcTrustyConnectWithSessionInitializer(
            kTrustyDefaultDeviceName, IStatsProxy::PORT().c_str(), session_initializer);
    LOG_ALWAYS_FATAL_IF(session == nullptr, "RpcTrustyConnectWithCallbackSession returned NULL");
    auto root = session->getRootObject();
    LOG_ALWAYS_FATAL_IF(root == nullptr, "getRootObject returned NULL");
    auto proxy = IStatsProxy::asInterface(root);
    LOG_ALWAYS_FATAL_IF(proxy == nullptr, "getRootObject returned NULL");

    proxy->initialize(statsBinderObject);

    // server->setRootObject(statsBinderObject);
    //  join will fail because server is nto completely initialized yet
    // server->join();
    while (true) std::this_thread::yield();

    // unreachable for now
    //(void)server->shutdown();
    std::ignore = session->shutdownAndWait(false);

    return EXIT_SUCCESS;
}
